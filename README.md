1. Design choices made
No overly-outlandish design choices were made. Likely the most unique thing I did was split my code into several different header files and even created a packet disector, hashing methods, and a dedicated container struct to simplify the functional portion of the code.

2. Problems encountered with the solution
Spent a lot of time struggling with the handshake, specifically with the "finished" message and deriving the same keys for both sides. Lots of effort went into debugging and trying to understand how the client and server were producing differing transcripts for the handshake message and thus producing incongruent shared-secrets.

3. Solutions to those problems.
There wasn't any one solution to these problems, there were several things that were broken, fixed, got broken again, and then had to be refixed or rewritten. Some of the major issues were the following:
- Server was attempting to build it's transcript during the handshake before it had built its complete Hello message. The fix was simply reordering the code to ensure transcripts were only built once all requisite data was procured.
- Originally used a system to permanently store the ephemeral and static keys for the server, but various issues caused the keys to persistently be overwritten and invalid, so I instead opted to store only the ephemeral key, loading and immediately unloading the static key the single time it was needed.
- Spent a large portion of time writing debugging/utility functions to provide truncated hashes of any binary data. This made it much easier to quickly find incongruities between the client and server. Ended up programming an entire TLV packet disector that prints readable summaries of packets and visually-displaying the TLV nesting and hierarchy that is otherwise very difficult to visualize.