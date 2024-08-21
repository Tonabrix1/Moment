# Moment
Quick sequence analyzer for finding timing attacks in web contexts


## Implemented
Extremely fast dispatch of responses and automatic substring iteration for sequence payloads, for example:
    Say the sequence used it a password "Pa$$", the tool will sent each substring "P", "Pa", "Pa$", and "Pa$$", then order the responses by response speed
    If the tool finds that the responses are ordered the same as the sequence above, it will prompt the user that a timing attack is very likely possible

Single packet mode which sends requests in an http/2 single packet attack to reduce/remove network jitter


## TODO
Implement response timing and analysis for single packet attacks to take full advantage of reduce network jitter