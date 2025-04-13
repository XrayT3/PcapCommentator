# Pcap Commentator

**Pcap Commentator** is a small Python tool that allows you to **add** and **read** comments from packets in `.pcapng` files using Scapy.

## Features

- ✅ Add a comment to a specific packet  
- 🔍 View a packet and its comment in JSON format  
- 📂 Save modified packets into a new `.pcapng` file  

## Usage
Edit the main.py to change the input file, comment text, and packet number.

Example:
```
add_comment_to_packet('your_input_file.pcapng', 'This is a comment.', 5)
read_comment_from_packet('output.pcapng', 5)
```

## Notes
The input file must be in `.pcapng` format (not `.pcap`)

Packet numbering starts at 1
