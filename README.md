# What is this?
Modern Binary Exploitation is the name of a course ran by [RPISEC](http://rpis.ec) at Rensselaer Polytechnic Institute in Spring 2015.
This repository contains my solutions to the course lab (materials available at their [github repository](https://github.com/RPISEC))

## About the course lab
The lab consists in a [WarZone game](https://github.com/RPISEC/MBE#labs---the-rpisec-warzone) (local privilege escalation themed game). The goal is to exploit a level to escalate
privileges and get the password of that user so you can log in as the new user and face the next challenge.

## About the exploits found here
I've tried to make every script self contained and very explanatory. You can find notes for for specific scripts inside the
level folder. The scripts are designed to exploit, store the password and quit. This means that they won't leave the user
with a shell (once we get the password, our objective is accomplished)

## Wzpass
wzpass is a tool I made to make logins and file copying easier with the WarZone. It makes use of sshpass to automate
the processes. With this tool you only need to copy/paste the password once (into a file) and then wzpass will read it
and handle the login for you. You can upload your exploits (if you decided to write them in your host machine) or download
a binary to reverse engineer with more powerful tools on your host machine (such as ida).

## Disclaimer
I am new to the cyber security world, and I am using this warzone to build up my hacking skills. There might be more
eficient ways of solving the problems found here, theese are my solutions.  
IMPORTANT: Note that looking at this solutions without even trying to solve the problems first, will ruin the fun of playing this
warzone. I strongly encourage the possible readers to try to solve the levels before reading my solutions. Please feel free to
contact me at evilgroot@gmail.com if you need help or just want to discuss a level.
