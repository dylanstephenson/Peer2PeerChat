# Overview

I created a networking program using Python tkinter that acts as a 2 way peer to peer chat between two devices on a network with TCP. This app runs with a GUI rather than through terminal. The application automatically detects your IP and selects a random port and displays the IP and port at the top of the GUI chat window. Below the chat window, there is Peer IP and Peer Port. This is where you put the IP and port of the device that you would like to send messages to. If the IP address and port are correct, the message will send, and you will also see a message on the sending device that the message was received. If not, there are descriptive errors provided.

I wrote this software to gain a better understanding of multiple devices on a network, and communicating between both of them. I wanted to see how it would work if the devices were on different OS, and if that would make a huge difference. I actually had less issues working the app between a Mac and a windows, then trying to get it to work between two macs on the same OS version.

[Software Demo Video](https://youtu.be/y19jbkK9oOY)

# Network Communication

Peer-to-Peer

TCP - Port is randomly selected when starting up the app, and displayed.

Message format is tkinter.scrolledtext

# Development Environment

VSCode

Python

# Useful Websites

- [YouTube - What is TCP/IP?](https://www.youtube.com/watch?v=PpsEaqJV_A0)
- [CloudFlare](https://www.cloudflare.com/learning/ddos/glossary/tcp-ip/)

# Future Work

- Update message formatting and color so it is easy to pick out the message
- Ability to be a "user" that sends messages through the app, and the message shows up in your name vs the IP and port number
- Update to use static porting. The automatic and randomly assigned ports were a result of troubleshooting, and adds a little extra complication I think.
