# NDN protocol

## Overview

MMT-DPI classifies Named Data Networking (NDN) traffic and extracts its
attributes. See the [packet format](./NDN-packet-format.md) and
[structure design](./NDN-design.md) pages for parsing details.

## View NDN packet in Wireshark

To view NDN packet in Wireshark application:

* Download script to ndn: `mmt-test/scripts/ndn.lua`

* Run wireshark from terminal with command: `wireshark -X lua_script:ndn.lua`


## Contents

[NDN packet format](./NDN-packet-format.md)

[Structure design](./NDN-design.md)

[Test case](./NDN-test-case.md)

[ChronoChat application](./ChronoChat.md)

[Documents](./NDN-documents.md)