Write a microservice in Go that implements a key-value store. A client package
that other microservices can use to call the store should be provided.

Please submit a link to a public repository containing your solution (e.g.
GitHub, GitLab, etc.). Alternatively link to a shared folder (e.g. Dropbox,
Google Drive, etc.) containing the repository can be submitted. We're also
happy with a tarball or similar of the git repository.

Transport and the service's interface are up to you. You're welcome to use Go's
standard library, third-party libraries, or frameworks you're familiar with.
There is no preference for one approach over another.

Stored data should be encrypted with a per-entry encryption key. There are no
particular requirements for how the data is stored, in-memory storage is
sufficient.

Your solution should be easy to run/verify. Please include any relevant
instructions, documentation, etc.

Implement the following operations.

STORE

Insert data into the store.

Inputs: data, ID.

Outputs: encryption key.

RETRIEVE

Retrieve data from the store.

Inputs: ID, encryption key.

Outputs: original data.

UPDATE

Update data in the store.

Inputs: new data, ID, encryption key.

Outputs: none.

DELETE

Remove data from the store.

Inputs: ID, encryption key.

Outputs: none.

Much like tools such as IDEs, AI assistants are becoming commonplace in
software development. As such their use is not forbidden, equally the task does
not require their use to complete. As with any code review process, candidates
are expected to be able to discuss and reason about their code, regardless of
how it was produced.

Aim to spend around 2 hours on this task; those new to Go may find they need
longer, but are encouraged to not spend significantly more once the above
key-value store is implemented.

---

Thoughts

Key Value store should have the backing datastore abstracted, with a postgres implementation and an in memory map implementation

A REST API is a sensible starting point. HTTP should be sufficient, gRPC would work equally well. Make sure you read up on pros and cons of each.

Must have bells and whistles:

- structured logging
- prometheus metrics
- abstracted backing datastore
- robust concurrency support

Structure:

- REST endpoints in main.go, calling functions in KeyValue.go
- KeyValue object defined in KeyValue.go
- Core functionality in KeyValue.go, calling abstractions of - a DataStore interface
- In Memory implementation
- Postgress implementation

Additional Notes:

- Leave detailed comments
- Include comments on time complexity of operations

Questions:

- What is it storing? That's been left open, so []byte would be logical
