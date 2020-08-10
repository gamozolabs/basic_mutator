//! Basic fuzzer mutation strategies

pub mod magic_values;

use core::convert::TryInto;
use magic_values::MAGIC_VALUES;

/// An empty database that never returns an input, useful for fuzzers without
/// corpuses or input databases.
pub struct EmptyDatabase;

impl InputDatabase for EmptyDatabase {
    fn num_inputs(&self) -> usize { 0 }
    fn input(&self, _idx: usize) -> Option<&[u8]> { None }
}

/// Routines to generically access a corpus/input database for a fuzzer. It's
/// up to the database to implement this trait, allowing generic access to
/// the number of inputs in the database, and accessors for a specific input.
///
/// The inputs should have zero-indexed IDs such that any input in the range of
/// [0, self.num_inputs()) should be a valid input.
///
/// If the `idx` does not lead to the same input each run, the determinism of
/// the mutator is unstable and can produce different results across different
/// runs.
pub trait InputDatabase {
    /// Get the number of inputs in the database
    fn num_inputs(&self) -> usize;

    /// Get an input with a specific zero-index identifier
    /// If the `idx` is invalid or otherwise not available, this returns `None`
    fn input(&self, idx: usize) -> Option<&[u8]>;
}

/// A basic random number generator based on xorshift64 with 64-bits of state
struct Rng(u64);

impl Rng {
    /// Generate a random number
    #[inline]
    fn next(&mut self) -> u64 {
        let val = self.0;
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 17;
        self.0 ^= self.0 << 43;
        val
    }

    /// Generates a random number with uniform distribution in the range of
    /// [min, max]
    #[inline]
    fn rand(&mut self, min: usize, max: usize) -> usize {
        // Make sure the range is sane
        assert!(max >= min, "Bad range specified for rand()");

        // If there is no range, just return `min`
        if min == max {
            return min;
        }
        
        // If the range is unbounded, just return a random number
        if min == 0 && max == core::usize::MAX {
            return self.next() as usize;
        }

        // Pick a random number in the range
        min + (self.next() as usize % (max - min + 1))
    }
    
    /// Generates a random number with exponential distribution in the range of
    /// [min, max] with a worst case deviation from uniform of 0.5x. Meaning
    /// this will always return uniform at least half the time.
    #[inline]
    fn rand_exp(&mut self, min: usize, max: usize) -> usize {
        if self.rand(0, 1) == 0 {
            // Half the time, provide uniform
            self.rand(min, max)
        } else {
            // Pick an exponentially difficult random number
            let x = self.rand(min, max);
            self.rand(min, x)
        }
    }
}

pub struct Mutator {
    /// Input vector to mutate, this is just an entire input files bytes
    ///
    /// It is strongly recommended that you do `input.clear()` and
    /// `input.extend_from_slice()` to update this buffer, to prevent the
    /// backing from being deallocated and reallocated.
    pub input: Vec<u8>,

    /// If non-zero length, this contains a list of valid indicies into
    /// `input`, indicating which bytes of the input should mutated. This often
    /// comes from instrumentation like access tracking or taint tracking to
    /// indicate which parts of the input are used. This will prevent us from
    /// corrupting parts of the input which have zero effect on the program.
    ///
    /// It's possible you can have this take any meaning you want, all it does
    /// is limit the corruption/splicing locations to the indicies in this
    /// vector. Feel free to change this to have different meanings, like
    /// indicate indicies which are used in comparison instructions!
    ///
    /// Since we use `rand_exp` to pick from this, this list should remain
    /// sorted for best behavior. If you cannot sort this, you should probably
    /// change the behaviors of `rand_offset` to be uniform
    ///
    /// It is strongly recommended that you do `accessed.clear()` and
    /// `accessed.extend_from_slice()` to update this buffer, to prevent the
    /// backing from being deallocated and reallocated.
    accessed: Vec<usize>,

    /// Maximum size to allow inputs to expand to
    max_input_size: usize,
    
    /// The random number generator used for mutations
    rng: Rng,

    /// The mutations should prefer creating ASCII-printable characters
    printable: bool,
}

/// A byte corruption skeleton which has user-supplied corruption logic which
/// will be used to mutate a byte which is passed to it
///
/// $corrupt takes a &mut self, `u8` as arguments, and returns a `u8` as the
/// corrupted value.
macro_rules! byte_corruptor {
    ($func:ident, $corrupt:expr) => {
        /// Corrupt a byte in the input
        fn $func(&mut self) {
            // Only corrupt a byte if there are bytes present
            if !self.input.is_empty() {
                // Pick a random byte offset
                let offset = self.rand_offset();

                // Perform the corruption
                self.input[offset] = ($corrupt)(self, self.input[offset]);

                // If we're in printable mode, wrap the value modulo the
                // printable boundaries
                if self.printable {
                    self.input[offset] =
                        self.input[offset].wrapping_sub(32) % 95 + 32;
                }
            }
        }
    }
}

impl Mutator { 
    /// Create a new mutator
    ///
    /// `max_input_size` specifies the maximum input size that will be produced
    /// and consumed by the mutator.
    ///
    /// `printable` specifies if the output should only contain ASCII printable
    /// characters
    ///
    /// `seed` specifies a seed for the random number generator
    pub fn new(max_input_size: usize, printable: bool, seed: u64) -> Self {
        Mutator {
            input:          Vec::new(),
            accessed:       Vec::new(),
            rng:            Rng(seed ^ 0x12640367f4b7ea35),
            max_input_size: max_input_size,
            printable:      printable,
        }
    }

    /// Performs standard mutation of an the input
    pub fn mutate<T: InputDatabase>(&mut self, mutations: usize, inputs: &T) {
        /// List of mutation strategies which do not require an input database
        const STRATEGIES: &[fn(&mut Mutator)] = &[
            Mutator::shrink,
            Mutator::expand,
            Mutator::bit,
            Mutator::inc_byte,
            Mutator::dec_byte,
            Mutator::neg_byte,
            Mutator::add_sub,
            Mutator::set,
            Mutator::swap,
            Mutator::copy,
            Mutator::inter_splice,
            Mutator::insert_rand,
            Mutator::overwrite_rand,
            Mutator::byte_repeat_overwrite,
            Mutator::byte_repeat_insert,
            Mutator::magic_overwrite,
            Mutator::magic_insert,
            Mutator::random_overwrite,
            Mutator::random_insert,
            Mutator::splice_overwrite,
            Mutator::splice_insert,
        ];

        for _ in 0..mutations {
            // Pick a random mutation strategy
            let sel = self.rng.rand(0, STRATEGIES.len() - 1);
                
            // Get the strategy
            let strat = STRATEGIES[sel];

            // Determine if we're doing an overwrite or insert splice strategy,
            // as we have to handle these a bit specially due to the use of
            // a generic input database.
            let splice_overwrite = std::ptr::eq(strat as *const (),
                Mutator::splice_overwrite as *const ());
            let splice_insert = std::ptr::eq(strat as *const (),
                Mutator::splice_insert as *const ());

            // Handle special-case mutations which need input database access
            if splice_overwrite || splice_insert {
                // Get the number of inputs in the database
                let dblen = inputs.num_inputs();
                if dblen == 0 { continue; }

                // Select a random input
                if let Some(inp) = inputs.input(self.rng.rand(0, dblen - 1)) {
                    // Nothing to splice for an empty input
                    if inp.is_empty() { continue; }

                    // Pick a random offset and length from the input which
                    // we want to use for splicing
                    let donor_offset = self.rng.rand_exp(0, inp.len() - 1);
                    let donor_length =
                        self.rng.rand_exp(1, inp.len() - donor_offset);

                    if splice_overwrite {
                        // Cannot overwrite an empty input
                        if self.input.is_empty() { continue; }

                        // Find an offset to overwrite in our input
                        let offset = self.rand_offset();
                        let length = core::cmp::min(donor_length,
                            self.input.len() - offset);

                        // Overwrite it!
                        self.overwrite(offset,
                            &inp[donor_offset..donor_offset + length]);
                    } else {
                        // Find an offset to insert at in our input
                        let offset = self.rand_offset_int(true);
                        let length = core::cmp::min(donor_length,
                            self.max_input_size - self.input.len());

                        // Insert!
                        self.insert(offset,
                            &inp[donor_offset..donor_offset + length]);
                    }
                }
            } else {
                // Run the mutation strategy
                strat(self);
            }

        }
    }

    /// Pick a random offset in the input to corrupt. Any mutation
    /// strategy which needs to pick a random byte should us this, such that
    /// a bias can be applied to the offsets and automatically affect all
    /// aspects of the fuzzer
    ///
    /// If `insert` is set to `true`, then the offset being returned is
    /// expected to be for insertion. This means that we'll have a chance of
    /// returning an offset before or after sections of the input. For example,
    /// we may return an index which is `self.input.len()`, which would allow
    /// for the user to insert data at the end of the input.
    ///
    /// If the input is zero length, then this will return a zero. Thus, it
    /// is up to the caller to know whether or not the input size being zero
    /// matters. For example, flipping a byte at offset 0 on a 0 size input
    /// would cause a panic, but inserting at offset 0 may be desired.
    fn rand_offset_int(&mut self, plus_one: bool) -> usize {
        if !self.accessed.is_empty() {
            // If we have an accessed list, use an index from the list of known
            // accessed bytes from the input. This prevents us from corrupting
            // a byte which cannot possibly influence the binary, as it is
            // never read during the fuzz case.
            self.accessed[self.rng.rand_exp(0, self.accessed.len() - 1)]
        } else if !self.input.is_empty() {
            // We have no accessed list, just return a random index
            self.rng.rand_exp(0, self.input.len() - (!plus_one) as usize)
        } else {
            // Input is entirely empty, just return index 0 such that
            // things that insert into the input know that they should
            // just insert at 0.
            0
        }
    }
    
    /// Generate a random offset, see `rand_offset_int` for more info
    fn rand_offset(&mut self) -> usize {
        self.rand_offset_int(false)
    }

    /// Dummy function, just used for RNG selection, logic is done in `mutate`
    fn splice_overwrite(&mut self) {}
    
    /// Dummy function, just used for RNG selection, logic is done in `mutate`
    fn splice_insert(&mut self) {}

    /// Randomly delete a chunk of the input
    fn shrink(&mut self) {
        // Nothing to do on an empty input
        if self.input.is_empty() {
            return;
        }

        // Pick a random offset to remove data at
        let offset = self.rand_offset();

        // Compute the number of bytes we could remove from this offset
        let can_remove = self.input.len() - offset;

        // Compute a maximum number of bytes to remove
        let max_remove = if self.rng.rand(0, 15) != 0 {
            // 15 in 16 chance of removing at most 16 bytes, this limits the
            // amount we remove in the most common case
            core::cmp::min(16, can_remove)
        } else {
            // 1 in 16 chance of removing a random amount of bytes to the end
            // of the input
            can_remove
        };

        // Pick the amount of bytes to remove
        let to_remove = self.rng.rand_exp(1, max_remove);

        // Remove the bytes from the input
        let _ = self.input.drain(offset..offset + to_remove);
    }
    
    /// Make space in the input, filling with zeros if `printable` is not
    /// set, and if it is set, then fill with spaces.
    fn expand(&mut self) {
        // Nothing to do if the input size is >= the cap
        if self.input.len() >= self.max_input_size {
            return;
        }

        // Pick a random offset to expand at
        let offset = self.rand_offset_int(true);

        // Calculate a maximum expansion size based on our maximum allowed
        // input size
        let max_expand = self.max_input_size - self.input.len();

        // Compute a maximum number of expansion bytes
        let max_expand = if self.rng.rand(0, 15) != 0 {
            // 15 in 16 chance of capping expansion to 16 bytes
            core::cmp::min(16, max_expand)
        } else {
            // 1 in 16 chance of uncapped expansion
            max_expand
        };

        // Create what to expand with
        let iter = if self.printable {
            core::iter::repeat(b' ').take(self.rng.rand_exp(1, max_expand))
        } else {
            core::iter::repeat(b'\0').take(self.rng.rand_exp(1, max_expand))
        };

        // Expand at `offset` with `iter`
        self.input.splice(offset..offset, iter);
    }

    /// Add or subtract a random amount with a random endianness from a random
    /// size `u8` through `u64`
    fn add_sub(&mut self) {
        // Nothing to do on an empty input
        if self.input.is_empty() {
            return;
        }

        // Pick an offset to corrupt at
        let offset = self.rand_offset();

        // Get the remaining number of bytes in the input
        let remain = self.input.len() - offset;

        // Pick a random size of the add or subtract as a 1, 2, 4, or 8 byte
        // signed integer
        let intsize = match remain {
            1..=1                => 1,
            2..=3                => 1 << self.rng.rand(0, 1),
            4..=7                => 1 << self.rng.rand(0, 2),
            8..=core::usize::MAX => 1 << self.rng.rand(0, 3),
            _ => unreachable!(),
        };

        // Determine the maximum number to add or subtract
        let range = match intsize {
            1 => 16,
            2 => 4096,
            4 => 1024 * 1024,
            8 => 256 * 1024 * 1024,
            _ => unreachable!(),
        };

        // Convert the range to a random number from [-range, range]
        let delta = self.rng.rand(0, range * 2) as i32 - range as i32;

        /// Macro to mutate bytes in the file as a `$ty`
        macro_rules! mutate {
            ($ty:ty) => {{
                // Interpret the `offset` as a `$ty`
                let tmp = <$ty>::from_ne_bytes(
                    self.input[offset..offset + intsize].try_into().unwrap());

                // Apply the delta, interpreting the bytes as a random
                // endianness
                let tmp = if self.rng.rand(0, 1) == 0 {
                    tmp.wrapping_add(delta as $ty)
                } else {
                    tmp.swap_bytes().wrapping_add(delta as $ty).swap_bytes()
                };

                // Write the new value out to the input
                self.input[offset..offset + intsize].copy_from_slice(
                    &tmp.to_ne_bytes());
            }}
        }

        // Apply the delta to the offset
        match intsize {
            1 => mutate!(u8),
            2 => mutate!(u16),
            4 => mutate!(u32),
            8 => mutate!(u64),
            _ => unreachable!(),
        };

        // If we're in printable mode, wrap the value modulo the
        // printable boundaries
        if self.printable {
            for offset in offset..offset + intsize {
                self.input[offset] =
                    self.input[offset].wrapping_sub(32) % 95 + 32;
            }
        }
    }
    
    /// Randomly replace a sequence of bytes with the same random character
    /// repeated a random amount of times
    fn set(&mut self) {
        // Nothing to do on an empty input
        if self.input.is_empty() {
            return;
        }

        // Pick offset to memset at
        let offset = self.rand_offset();

        // Pick random length to remainder of file
        let len = self.rng.rand_exp(1, self.input.len() - offset);

        // Pick the value to memset
        let chr = if self.printable {
            (self.rng.rand(0, 94) + 32) as u8
        } else {
            self.rng.rand(0, 255) as u8
        };

        // Replace the selected bytes at the offset with `chr`
        self.input[offset..offset + len].iter_mut().for_each(|x| *x = chr);
    }

    /// Swap two ranges in an input buffer
    fn swap_ranges(vec: &mut [u8], mut offset1: usize, mut offset2: usize,
                   mut len: usize) {
        if offset1 < offset2 && offset1 + len >= offset2 {
            // [o1-------]
            //     [o2-------]
            let tail = offset2 - offset1;
            for ii in (tail..len).rev() {
                vec[offset2 + ii] = vec[offset1 + ii];
            }

            len = tail;
        } else if offset2 < offset1 && offset2 + len >= offset1 {
            //     [o1-------]
            // [o2-------]
            let head = len - (offset1 - offset2);
            for ii in 0..head {
                vec[offset2 + ii] = vec[offset1 + ii];
            }
            
            offset1 += head;
            offset2 += head;
            len     -= head;
        }

        for ii in 0..len {
            vec.swap(offset1 + ii, offset2 + ii);
        }
    }

    /// Swap two difference sequence of bytes in the input to different places
    fn swap(&mut self) {
        // Nothing to do on an empty input
        if self.input.is_empty() {
            return;
        }

        // Pick two random ranges in the input and calculate the remaining
        // bytes for them
        let src    = self.rand_offset();
        let srcrem = self.input.len() - src;
        let dst    = self.rand_offset();
        let dstrem = self.input.len() - dst;

        // Pick a random length up to the max for both offsets
        let len = self.rng.rand_exp(1, core::cmp::min(srcrem, dstrem));

        // Swap the ranges of bytes
        Self::swap_ranges(&mut self.input, src, dst, len);
    }

    /// Insert `buf` at `offset` in the input. `buf` will be truncated to
    /// ensure the input stays within the maximum input size
    fn insert(&mut self, offset: usize, buf: &[u8]) {
        // Make sure we don't expand past the maximum input size
        let len =
            core::cmp::min(buf.len(), self.max_input_size - self.input.len());

        // Splice in the `buf`
        self.input.splice(offset..offset, buf[..len].iter().copied());
        
        // If we're in printable mode, wrap the value modulo the
        // printable boundaries
        if self.printable {
            for offset in offset..offset + len {
                self.input[offset] =
                    self.input[offset].wrapping_sub(32) % 95 + 32;
            }
        }
    }

    /// Overwrite the bytes in the input with `buf` at `offset`. If `buf`
    /// goes out of bounds of the input the `buf` will be truncated and the
    /// copy will stop.
    fn overwrite(&mut self, offset: usize, buf: &[u8]) {
        // Get the slice that we may overwrite
        let target = &mut self.input[offset..];

        // Get the length to overwrite
        let len = core::cmp::min(buf.len(), target.len());

        // Overwrite the bytes
        target[..len].copy_from_slice(&buf[..len]);
        
        // If we're in printable mode, wrap the value modulo the
        // printable boundaries
        if self.printable {
            for offset in offset..offset + len {
                self.input[offset] =
                    self.input[offset].wrapping_sub(32) % 95 + 32;
            }
        }
    }

    /// Take the bytes from `source` for `len` bytes in the input, and insert
    /// a copy of them at `dest`
    fn insert_inplace(&mut self, source: usize, len: usize, dest: usize) {
        // Nothing to do
        if len == 0 || source == dest { return; }

        // Cap the insertion to the max input size
        let len = core::cmp::min(len, self.max_input_size - self.input.len());

        // Create an interator to splice into the input
        let rep = core::iter::repeat(b'\0').take(len);

        // Expand at `dest` with `rep`, making room for the copy
        self.input.splice(dest..dest, rep);

        // Determine where the splice occurred
        let split_point = dest.saturating_sub(source).min(len);

        for ii in 0..split_point {
            self.input[dest + ii] = self.input[source + ii];
        }
        
        for ii in split_point..len {
            self.input[dest + ii] = self.input[source + ii + len];
        }
    }
    
    /// Take the bytes from `source` for `len` bytes in the input, and copy
    /// them to `dest`
    fn overwrite_inplace(&mut self, source: usize, len: usize, dest: usize) {
        // Nothing to do
        if len == 0 || source == dest { return; }

        if source < dest {
            // Copy forwards
            for ii in 0..len {
                self.input[dest + ii] = self.input[source + ii];
            }
        } else {
            // Copy backwards
            for ii in (0..len).rev() {
                self.input[dest + ii] = self.input[source + ii];
            }
        }
    }
    
    /// Copy bytes from one location in the input and overwrite them at another
    /// location in the input
    fn copy(&mut self) {
        // Nothing to do on an empty input
        if self.input.is_empty() {
            return;
        }

        // Pick a source and destination for a copy
        let src    = self.rand_offset();
        let srcrem = self.input.len() - src;
        let dst    = self.rand_offset();
        let dstrem = self.input.len() - dst;

        // Pick a random length up to the max for both offsets
        let len = self.rng.rand_exp(1, core::cmp::min(srcrem, dstrem));

        // Perform a copy inplace in the input
        self.overwrite_inplace(src, len, dst);
    }
    
    /// Take one location of the input and splice it into another
    fn inter_splice(&mut self) {
        // Nothing to do on an empty input
        if self.input.is_empty() {
            return;
        }

        // Pick a source and destination for an insertion
        let src    = self.rand_offset();
        let srcrem = self.input.len() - src;
        let dst    = self.rand_offset_int(true);

        // Pick a random length
        let len = self.rng.rand_exp(1, srcrem);

        // Perform an insertion inplace in the input
        self.insert_inplace(src, len, dst);
    }

    /// Create 1 or 2 random bytes and insert them into the input
    fn insert_rand(&mut self) {
        // Pick some random values
        let bytes = if self.printable {
            [
                (self.rng.rand(0, 94) + 32) as u8,
                (self.rng.rand(0, 94) + 32) as u8,
            ]
        } else {
            [self.rng.rand(0, 255) as u8, self.rng.rand(0, 255) as u8]
        };

        // Pick a random offset and length
        let offset = self.rand_offset_int(true);
        let len = self.rng.rand(1, 2);

        // Insert the bytes
        self.insert(offset, &bytes[..len]);
    }
    
    /// Create 1 or 2 random bytes and overwrite them at a location in the
    /// input
    fn overwrite_rand(&mut self) {
        // Nothing to do on an empty input
        if self.input.is_empty() {
            return;
        }

        // Pick some random values
        let bytes = if self.printable {
            [
                (self.rng.rand(0, 94) + 32) as u8,
                (self.rng.rand(0, 94) + 32) as u8,
            ]
        } else {
            [self.rng.rand(0, 255) as u8, self.rng.rand(0, 255) as u8]
        };

        // Pick a random offset and length
        let offset = self.rand_offset();
        let len = core::cmp::min(self.input.len() - offset, 2);
        let len = self.rng.rand(1, len);

        // Overwrite the bytes
        self.overwrite(offset, &bytes[..len]);
    }

    /// Find a byte and repeat it multiple times by overwriting the data after
    /// it
    fn byte_repeat_overwrite(&mut self) {
        // Nothing to do on an empty input
        if self.input.is_empty() {
            return;
        }

        // Pick a random offset
        let offset = self.rand_offset();

        // Pick an amount to repeat
        let amount = self.rng.rand_exp(1, self.input.len() - offset);

        // Get the old value and repeat it
        let val = self.input[offset];
        self.input[offset + 1..offset + amount]
            .iter_mut().for_each(|x| *x = val);
    }
    
    /// Find a byte and repeat it multiple times by splicing a random amount
    /// of the byte in
    fn byte_repeat_insert(&mut self) {
        // Nothing to do on an empty input
        if self.input.is_empty() {
            return;
        }

        // Pick a random offset
        let offset = self.rand_offset();

        // Pick an amount to repeat, subtracting one to account for the byte
        // we're copying itself
        let amount = self.rng.rand_exp(1, self.input.len() - offset) - 1;

        // Make sure we don't expand past the maximum input size
        let amount =
            core::cmp::min(self.max_input_size - self.input.len(), amount);

        // Get the value we want to repeat
        let val = self.input[offset];

        // Create an interator we want to expand with
        let iter = core::iter::repeat(val).take(amount);

        // Expand at `offset` with `iter`
        self.input.splice(offset..offset, iter);
    }
    
    /// Write over the input with a random magic value
    fn magic_overwrite(&mut self) {
        // Nothing to do on an empty input
        if self.input.is_empty() {
            return;
        }

        // Pick a random offset
        let offset = self.rand_offset();

        // Pick a random magic value
        let magic_value = 
            &MAGIC_VALUES[self.rng.rand(0, MAGIC_VALUES.len() - 1)];

        // Overwrite it
        self.overwrite(offset, magic_value);
    }
    
    /// Inject a magic value into the input
    fn magic_insert(&mut self) {
        // Pick a random offset
        let offset = self.rand_offset_int(true);

        // Pick a random magic value
        let magic_value = 
            &MAGIC_VALUES[self.rng.rand(0, MAGIC_VALUES.len() - 1)];

        // Insert it
        self.insert(offset, magic_value);
    }
    
    /// Overwrite a random offset of the input with random bytes
    fn random_overwrite(&mut self) {
        // Nothing to do on an empty input
        if self.input.is_empty() {
            return;
        }

        // Pick a random offset
        let offset = self.rand_offset();

        // Pick an amount to overwrite
        let amount = self.rng.rand_exp(1, self.input.len() - offset);

        // Overwrite with random data
        let rng = &mut self.rng;
        if self.printable {
            self.input[offset..offset + amount]
                .iter_mut().for_each(|x| {
                    *x = (rng.rand(0, 94) + 32) as u8;
                });
        } else {
            self.input[offset..offset + amount]
                .iter_mut().for_each(|x| *x = rng.rand(0, 255) as u8);
        }
    }
    
    /// Insert random bytes into a random offset in the input
    fn random_insert(&mut self) {
        // Pick a random offset
        let offset = self.rand_offset_int(true);
        
        // Pick an amount to insert
        let amount = self.rng.rand_exp(0, self.input.len() - offset);

        // Make sure the amount doesn't expand us past the maximum input size
        let amount = core::cmp::min(amount,
            self.max_input_size - self.input.len());

        // Insert `amount` random bytes
        let rng = &mut self.rng;
        if self.printable {
            self.input.splice(offset..offset, (0..amount).map(|_| {
                (rng.rand(0, 94) + 32) as u8
            }));
        } else {
            self.input.splice(offset..offset, (0..amount).map(|_| {
                rng.rand(0, 255) as u8
            }));
        }
    }
    
    // Corrupt a random bit in the input
    byte_corruptor!(bit, |obj: &mut Self, x: u8| -> u8 {
        x ^ (1u8 << obj.rng.rand(0, 7))
    });
    
    // Increment a byte in the input
    byte_corruptor!(inc_byte, |_: &mut Self, x: u8| -> u8 {
        x.wrapping_add(1)
    });
    
    // Decrement a byte in the input
    byte_corruptor!(dec_byte, |_: &mut Self, x: u8| -> u8 {
        x.wrapping_sub(1)
    });
    
    // Negate a byte in the input
    byte_corruptor!(neg_byte, |_: &mut Self, x: u8| -> u8 {
        !x
    });
}

#[test]
fn simple_example() {
    // Create a seeded mutator with a maximum size of 128 bytes for printable
    // ASCII characters
    let mut mutator = Mutator::new(128, true, 0xd7ebfe9b8e89fa50);

    for _ in 0..32 {
        // Update the input
        mutator.input.clear();
        mutator.input.extend_from_slice(b"APPLES ARE DELICIOUS");

        // Corrupt it with 4 mutation passes
        mutator.mutate(4, &EmptyDatabase);

        // Just print the string
        println!("{:?}", String::from_utf8_lossy(&mutator.input));
    }
}

#[test]
fn feedback_example() {
    // Create a fake database which will be used to select inputs from a fake
    // feedback dattabase
    struct TestDatabase;
    impl InputDatabase for TestDatabase {
        fn num_inputs(&self) -> usize { 1 }
        fn input(&self, _idx: usize) -> Option<&[u8]> { Some(b"thisisatest") }
    }

    // Create a seeded mutator with a maximum size of 128 bytes for printable
    // ASCII characters
    let mut mutator = Mutator::new(128, true, 0xd7ebfe9b8e89fa50);

    for _ in 0..32 {
        // Update the input
        mutator.input.clear();
        mutator.input.extend_from_slice(b"APPLES ARE DELICIOUS");

        // Corrupt it with 4 mutation passes
        mutator.mutate(4, &TestDatabase);

        // Just print the string
        println!("{:?}", String::from_utf8_lossy(&mutator.input));
    }
}

