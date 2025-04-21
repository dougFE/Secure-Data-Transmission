# Description of Work (10 points)

We ask you to include a file called `README.md` that contains a quick description of:

1. the design choices you made,
No overly exciting design choices were made. Likely the most unique thing I did was split my code into several different header files and even created a container struct to make passing buffers less of a pain. 

2. any problems you encountered while creating your solution, and
Spent a lot of time struggling with the handshake, specifically with the "finished" message and deriving the same keys for both sides. Lots of effort went into debugging and trying to understand how the client and server were producing different transcripts for the handshake message.

3. your solutions to those problems.
There wasn't any one solution to these problems, there were several things that were broken, fixed, got broken again, and then had to be refixed or rewritten. Some of the major issues were the following:
- Server was attempting to build it's transcript during the handshake before it had built its complete Hello message. 
- Originally used a system to permanently store the ephemeral and static keys for the server, but some mysterious issues caused the keys to persistently be wrong so I instead opted to use only the ephemeral key, loading and immediately unloading the static key the one time it was needed.
- Spent longer than I should have writing debugging functions to provide truncated hashes of any binary data. This made it much easier to quickly find incongruities between the client and server, but I admit it was likely not worth the time or effort for such a short term project.