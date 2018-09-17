## Description

### How to Test
FirewallTest.py is the unit test for Firewall class, which includes testing methods for all the functions in Firewall class.<\>
- Test Method1:
Use pyCharm IDE, open the project Firewall and Run unittest in FirewallTest
- Test Method2:
Use Command unit test `python -m unittest Firewall/FirewallTest.py`

### Design and Analysis
For the implementation of accept_packet function, we need search rules from big cvs files, space and time are two
challenges for this question, especially memory space. So we need filter the data using a generator function since
just need to check whether the input parameter match. By this way we only hold one row in memory. As long as it finds
the rule, it will return and stop.

### Interested Area
data team
- Internship experience in Business Intelligence & Telemetry team working with big data and data analytics
- Have passion in data engineering/data science career in the future
