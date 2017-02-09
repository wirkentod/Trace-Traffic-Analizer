import csv
import os
import sys
file = open(sys.argv[1], 'rb')
ids = csv.reader(file)
dirname_results = '../AppEscalable/Results'
#Las funciones que se utilizaran
def calcular_parametros_directorio(id):
        #m_max: max directory, n_max: max sub_directory, p_max: max files per directory
        m_max = 1000 ;n_max = 100; p_max = 1000
        if (id % p_max ) == 0:
                p = p_max
        else:
                p = id % (p_max)
        n = 1 + (((id - p)/p_max) % n_max)
        m = 1+ ((((id-p)/p_max) - (n-1))/n_max)
        return [n,m]

for id in ids:
	[n,m] = calcular_parametros_directorio(int(id[0]))
    	dir_flow_id = dirname_results+'/Flow_'+str(m)+'/Flow_'+str(m)+'_'+str(n)
	os.system("rm "+dir_flow_id+"/flow_value_"+id[0]+".csv ./ExportData")
file.close()
