# Summary

This is a simple mutator largely based on
[honggfuzz](https://github.com/google/honggfuzz). This is all written in safe
Rust and provides abstractions to allow for coverage guided fuzzing as well as
taint guided fuzzing.

This provides no harnessing or injection into a target, this is purely a
library which can be used to take in streams of bytes and produce mutated
streams of bytes.

# Usage

First, create a project with `basic_mutator` as a dependency in your
`Cargo.toml`

```
[dependencies]
basic_mutator = { git = "https://github.com/gamozolabs/basic_mutator" }
```

To use this mutator, simply create a `Mutator`. This is done by calling
`Mutator::new` with a maximum input size, a bool indicating whether or not the
input is ASCII-printable only, and a random seed to seed the internal RNG.

A seed should be provided in all cases via the builder syntax, eg,
`Mutator::new().seed(0xdeadbeef)`. _The mutator has no source of external
entropy and thus without a seed will produce the same sequence of mutations._

Once this `Mutator` has been created, fill `mutator.input`, a public `Vec<u8>`
member, with the input you want to mutate. It is highly encouraged that you use
`mutator.input.clear()` and `mutator.input.extend_from_slice()` rather than
things like `clone()`, to re-use the existing `mutator.input` allocation. This
entire library performs no allocations other than expanding the `mutator.input`
up to the maximum size specified. If this input buffer is reused, there will be
no allocations occuring during normal operation.

Once the input has been filled in, call `mutator.mutate()` and provide a
number of mutations, and a reference to a type which implements
`InputDatabase`. If you don't have an input database, you can provide
`&EmptyDatabase`, a implementation which will always return an empty database.

Once `mutate` is complete, the `mutate.input` now contains a mutated input!

# Advanced Usage

This mutator library has support for both coverage guided fuzzing and taint
guided fuzzing.

## Coverage Guided Fuzzing

If you're using a corpus of inputs, or even better, an input database which
grows dynamically based on coverage, you're in luck! When calling
`mutator.mutate`, provide a reference to a type which implements
`InputDatabase`.

This `InputDatabase` trait requires that you implement two methods.
`num_inputs()` which returns a `usize`, indicating the number of inputs in the
input database, as well as `input()` which takes a `usize` index and returns
the corresponding input in the database.

When this trait is implemented and a non-empty database is provided, the fuzzer
will use spicing strategies to take random pieces from existing inputs and
insert or overwrite them into a random location in the input being corrupted.

## Taint Guided Fuzzing

In an environment where you have some level of taint tracking, you can use the
`mutator.accessed` vector. This vector is a `Vec<usize>` and contains indicies
of locations where corruptions should occur. It is up to the user to make sure
this information is meaningful. A great starting point is to track which bytes
of the input are read from the input file or from memory, and only include
those indicies in the `accessed` vector. This will prevent the mutator from
mutating parts of the input which never are actually used by a program.

This logic is largely unbounded, and all we do internally is use this
`accessed` vector as a restriction of mutation boundaries. This could be used
by a symbolic execution engine which is providing offsets in the input
which are used during the calculation of a branch which is being solved/fuzzed.

# Example

## Basic example

Here's a basic example with no corpus or `accessed` guidance.

```rust
fn simple_example() {
    // Create a mutator for 128-byte ASCII printable inputs
    let mut mutator = Mutator::new().seed(1337)
        .max_input_size(128).printable(true);

    for _ in 0..128 {
        // Update the input
        mutator.input.clear();
        mutator.input.extend_from_slice(b"APPLES ARE DELICIOUS");

        // Corrupt it with 4 mutation passes
        mutator.mutate(4, &EmptyDatabase);
        assert!(mutator.input.len() <= 128);

        // Just print the string
        println!("simple: {}", String::from_utf8_lossy(&mutator.input));
    }
}
```

## Corpus example

Here's a basic example with a simple fixed corpus.

```rust
fn corpus_example() {
    // Create a fake database which will be used to select inputs from a fake
    // feedback dattabase
    struct TestDatabase;
    impl InputDatabase for TestDatabase {
        fn num_inputs(&self) -> usize { 2 }
        fn input(&self, idx: usize) -> Option<&[u8]> {
            match idx {
                0 => Some(b"thisisatest"),
                1 => Some(b"wafflesaregood"),
                _ => unreachable!(),
            }
        }
    }

    // Create a mutator for 128-byte ASCII printable inputs
    let mut mutator = Mutator::new().seed(1337)
        .max_input_size(128).printable(true);

    for _ in 0..128 {
        // Update the input
        mutator.input.clear();
        mutator.input.extend_from_slice(b"APPLES ARE DELICIOUS");

        // Corrupt it with 4 mutation passes
        mutator.mutate(4, &TestDatabase);
        assert!(mutator.input.len() <= 128);

        // Just print the string
        println!("feedback: {}", String::from_utf8_lossy(&mutator.input));
    }
}
```

