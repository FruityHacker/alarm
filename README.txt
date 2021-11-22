README.txt
Max Morningstar (mmorni01)

Implemented Features
  At this point, alarm.py is mostly functional. Some bugs exist: the methodology
  behind my Nikto check may be flawed, and I am unable to detect the HTTP password
  in set2.pcap. Other minor issues may occur, however to my knowledge everything
  else is implemented as asked.

Collaboration
  I did almost all of the lab solo, however I did talk with Deanna Oei (a friend
  from Discrete, which we are both taking this semester) about how to go about
  catching an SMB scan. I of course consulted many forums throughout the project,
  though always as a reader and not as a poster/commenter.

Time Spent
  I spent in the neighborhood of 8-10 hours on this assignment

Additional Dependencies
  re - for string manipulation
  base64 - for base64 decoding when hunting for passwords

Additional Questions:
  Are the heuristics used in this assignment to determine incidents "even that good"?
    Some are better than others. It is very obvious when someone is attempting a
    Null scan because you would rarely, if at all, encounter a packet with all
    three flags shut off. However, when you consider a feature like SMB which
    technically could be used legitimately, it does begin to call into question
    just how effective this system would be at spotting actual attacks, and not
    just getting bogged down by harmless internet traffic.

  If you have spare time in the future, what would you add to the program or do differently with regards to detecting incidents?
    I would try to better dive into what separates a legitimate use of a port
    or flag from a deliberate use to probe a network. For instance, I think I
    drew a lot of false positives for FIN scans because that is a flag that
    inevitably gets used by people on a network. We don't want the alarm going
    off too often - as we said (in class or on Piazza, I don't recall) if the
    alarm is constantly going off, we tend as humans to eventually just tune it out.
