Date Format
===============

Many of the kadmin commands take a duration or time as an argument. The date can appear in a wide variety of formats, such as::

     "15 minutes"
     "7 days"
     "1 month"
     "2 hours"
     "400000 seconds"
     "next year"
     "this Monday"
     "next Monday"
     yesterday
     tomorrow
     now
     "second Monday"
     fortnight
     "3/31/1992 10:00:07 PST"
     "January 23, 2007 10:05pm"
     "22:00 GMT"
     

The following is a list of all of the allowable keywords.

========================== ============================================
Months                      january, jan, february, feb, march, mar, april, apr, may, june, jun, july, jul, august, aug, september, sep, sept, october, oct, november, nov, december, dec 
Days                        sunday, sun, monday, mon, tuesday, tues, tue, wednesday, wednes, wed, thursday, thurs, thur, thu, friday, fri, saturday, sat 
Units                       year, month, fortnight, week, day, hour, minute, min, second, sec 
Relative                    tomorrow, yesterday, today, now, last, this, next, first, second, third, fourth, fifth, sixth, seventh, eighth, ninth, tenth, eleventh, twelfth, ago 
Time Zones                  kadmin recognizes abbreviations for most of the world's time zones. A complete listing appears in kadmin Time Zones. 
12-hour Time Delimiters     am, pm
========================== ============================================


.. note:: If the date specification contains spaces, you must enclose it in double quotes. Note also that you cannot use a number without a unit. (I.e., ""60 seconds"" is correct, but "60" is incorrect.) All keywords are case-insensitive.


------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___db

