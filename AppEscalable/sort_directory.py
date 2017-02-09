import os
dirname_traces='../AppEscalable/Traces'
for file_trace in sorted(os.listdir(dirname_traces)):
	print "File primer niver: %s" %(file_trace)
	for file in sorted(os.listdir(str(dirname_traces+'//'+file_trace))):
		print "File segundo nivel: %s" %(file)

