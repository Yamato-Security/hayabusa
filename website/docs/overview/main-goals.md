# Main Goals

## Threat Hunting and Enterprise-wide DFIR

Hayabusa currently has over 4000 Sigma rules and over 170 Hayabusa built-in detection rules with more rules being added regularly.
It can be used for enterprise-wide proactive threat hunting as well as DFIR (Digital Forensics and Incident Response) for free with [Velociraptor](https://docs.velociraptor.app/)'s [Hayabusa artifact](https://docs.velociraptor.app/exchange/artifacts/pages/windows.eventlogs.hayabusa/).
By combining these two open-source tools, you can essentially retroactively reproduce a SIEM when there is no SIEM setup in the environment.
You can learn about how to do this by watching [Eric Capuano](https://twitter.com/eric_capuano)'s Velociraptor walkthrough [here](https://www.youtube.com/watch?v=Q1IoGX--814).

## Fast Forensics Timeline Generation

Windows event log analysis has traditionally been a very long and tedious process because Windows event logs are 1) in a data format that is hard to analyze and 2) the majority of data is noise and not useful for investigations.
Hayabusa's goal is to extract out only useful data and present it in a concise as possible easy-to-read format that is usable not only by professionally trained analysts but any Windows system administrator.
Hayabusa hopes to let analysts get 80% of their work done in 20% of the time when compared to traditional Windows event log analysis.

![DFIR Timeline](../assets/doc/DFIR-TimelineCreation-EN.png)
