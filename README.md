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
