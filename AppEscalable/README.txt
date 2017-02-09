#Install dependences:
$ sudo apt-get install python
$ sudo apt-get install vim
$ sudo apt-get install git

$ git clone https://github.com/wirkentod/pypcapfile.git
$ ./setup.py install
$ git clone https://github.com/wirkentod/Trace-Traffic-Analizer.git

#Save traces traffic, pcap format, in directory ./Traces
#You could organize each trace in a sub-directory
#To see the list of traces sorted if there is data in ./Traces
$ python sort_directory.py

#Figure out Internet Flows
$ python exe_flows.py
#Internet Flows are saved in ./Results
#There is a brief summary in ./Dicts

#If you want export data from specific id's first you should have a ids.csv file which contain id's number
$ python exportDataById.py ids.csv
#All the ids selected are saved in ./ExportData
#You can make a tar to ./ExportData to work in your specific framework

