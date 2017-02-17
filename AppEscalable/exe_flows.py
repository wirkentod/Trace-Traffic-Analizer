from pcapfile import savefile
from pcapfile.protocols.linklayer import ethernet
from pcapfile.protocols.network import ip
from pcapfile.protocols.transport import tcp
from pcapfile.protocols.transport import udp
import binascii
import csv
import sys
import time
import ctypes
import traceback
import os
Flows={}
line_count = 0; total_lines = 0
MaxId = 0; cant_packet = 0; arrivalTime = 0; elapsed = 0
file_trace_now = ''
dirname_traces = '../AppEscalable/Traces'
dirname_results = '../AppEscalable/Results'

#Cargamos el diccionario
start_dict = time.clock()
try:
	for key, val1, val2, val3 in csv.reader(open('./Dicts/dict.csv')):
		Flows[str(key)] = [int(val1), int(val2) , int(val3)]
	#Cargamos el valor de MaxId
	for row in csv.reader(open('./Dicts/val_ini.csv')):
		MaxId = int(row[0]); cant_packet = int(row[1]); arrivalTime = float(row[2]); time_old = float(row[3])
        	elapsed = float(row[4])
	elapsed_dict = time.clock() - start_dict
except IOError:
	#Parametro al inicio de ejecucion
	pass
		
elapsed_dict = time.clock() - start_dict
print "Dict load time: %s segundos" % (elapsed_dict)

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

for dir_trace in sorted(os.listdir(dirname_traces)):
	print "File primer nivel: %s" %(dir_trace)
	#Se analiza cada sub-traza que esta en el directorio */Traces
	for file_trace in sorted(os.listdir(str(dirname_traces+'//'+dir_trace))):
		
		start1=time.clock()
		print "File: %s" %(file_trace)
		file_trace_now = file_trace	
		input_file = open(dirname_traces+'//'+dir_trace+'//'+file_trace, 'rb')
		#Se crea el header
		header = savefile._load_savefile_header(input_file)
		
		if savefile.__validate_header__(header):
			#Se empieza a leer paquete por paquete del archivo input_file
			while True:
				#Leemos un paquete
				pkt =savefile. _read_a_packet(input_file, ctypes.pointer(header), 0)
				cant_packet += 1
				line_count += 1
				
				if line_count == 100000:
					total_lines += line_count
					print " %d Lineas Procesadas" %total_lines
					line_count = 0		

				if pkt:
					try:
						eth_frame = ethernet.Ethernet(pkt.raw())
						#Analisis si el paquete tiene el campo Vlan
						frame = eth_frame.payload
						validador_vlan= frame[4:8]
						validador_ip = frame[8:10]
						#Si el paquete cumple las condiciones, contiene el header vlan
						if validador_vlan == "0800" and validador_ip == "45":
							eth_frame.payload = frame[8:]		
						ip_packet = ip.IP(binascii.unhexlify(eth_frame.payload))
						#se procede a extraeir los datos de la capa 3
						capa3 = str(ip_packet).split(";")
						ip_src = capa3[0]
						ip_dst = capa3[1]
						protocolo = capa3[2]
						ip_hl = capa3[3]
						size_pkt = pkt.packet_len
						#Capturamos los arrivalTimes de cada paquete
						time_present = float(pkt.timestamp_us)*0.000001+float(pkt.timestamp)
						
						if cant_packet == 1: 
							time_old = time_present
						deltaTime = time_present - time_old
						time_old = time_present
						arrivalTime += deltaTime
						
						#se procede a extraer los datos de la capa 4, se coloca 40 pues es a partir
						#de este valor que comienza el payload de la capa de transporte
						
						#creamos los bits de los flags SYN y FIN
						bit_SYN='0';bit_FIN='0'
						#si el protocolo es TCP
						if (int(protocolo) == 6):
							try:
								tcp_packet = tcp.TCP(binascii.unhexlify(eth_frame.payload[40:]))
								#Extraemos los datos de la capa 4
								capa4_tcp = str(tcp_packet).split(";")
								port_src = capa4_tcp[0]
								port_dst = capa4_tcp[1]
								seqnum_tcp = capa4_tcp[2]
								acknum_tcp = capa4_tcp[3]
								data_offset_tcp = capa4_tcp[4]
								bit_urg = capa4_tcp[5]
								bit_ack = capa4_tcp[6]
								bit_psh = capa4_tcp[7]
								bit_rst = capa4_tcp[8]
								bit_syn = capa4_tcp[9]
								bit_fin = capa4_tcp[10]
								win_tcp = capa4_tcp[11]
							except:
								port_src = '0'
								port_dst = '0'
						#si el protocolo es UDP
						elif (int(protocolo) == 17):
							try:
								udp_packet = udp.UDP(binascii.unhexlify(eth_frame.payload[40:]))
								#Extraemos los datos de la capa 4
								capa4_udp = str(udp_packet).split(";")
								port_src = capa4_udp[0]
								port_dst = capa4_udp[1]	
							except:
								port_src = '0'
								port_dst = '0'
						#para otros protocolos
						else:
							port_src = '0'; port_dst = '0'
						#Se defina la variable temporal para los flags UP_DW (uplink and downlink)
						temp_FLAG_UP_DW=0
						#key rule: lower IP comes first
						if (ip_src < ip_dst):
							temp_FLAG_UP_DW=1
							temp_key=ip_src+'&'+ip_dst+'&'+protocolo+'&'+port_src+'&'+port_dst
						else:
							temp_key=ip_dst+'&'+ip_src+'&'+protocolo+'&'+port_dst+'&'+port_src
						
						#Si el paquete pertenece a un nuevo Flow 
						if (Flows.has_key(str(temp_key))==False):
							#Agregamos los valores del Flow con 0
							MaxId += 1
							#Los valores son [Id, pktCount, sizeFlow]
							values = [MaxId, 0, 0]
							curDict = {str(temp_key): values}
							Flows.update(curDict)
							#Creamos el directorio donde se guardara las caracteristicas del Flow
							[n,m] = calcular_parametros_directorio(MaxId)
							dir_flow = dirname_results+'/Flow_'+str(m)+'/Flow_'+str(m)+'_'+str(n)
							try:
								os.makedirs(dir_flow)
							except OSError:
								pass
							
						old_value_flow = Flows[str(temp_key)]
						#Actualizamos los valores del Flow
						old_value_flow[1] += 1
						old_value_flow[2] += size_pkt
						
						#Guardamos los valores dinamicos del Flow
						[n,m] = calcular_parametros_directorio(old_value_flow[0])
						dir_flow_pkt = dirname_results+'/Flow_'+str(m)+'/Flow_'+str(m)+'_'+str(n)
						file_pkt = open(dir_flow_pkt+'/flow_value_'+str(old_value_flow[0])+'.csv', 'a')
						#Se escribe el header de cada paquete
						if (int(protocolo) == 6):
							pkt_payload = size_pkt - (14 + 4*int(ip_hl) + int(data_offset_tcp))
							print "paquete TCP %s: %s | %s | %s | %s " %(cant_packet , size_pkt, ip_hl, data_offset_tcp, pkt_payload )
							file_pkt.write(str(old_value_flow[1]) + ',' + str(arrivalTime) + ',' + str(size_pkt) + ',' + str(temp_FLAG_UP_DW)  + ',' + str(pkt_payload) + ',' + str(seqnum_tcp) + ',' + str(acknum_tcp) + ',' + str(data_offset_tcp) + ',' + str(bit_urg) + ',' + str(bit_ack) + ',' + str(bit_psh) + ',' + str(bit_rst) + ',' + str(bit_syn) + ',' + str(bit_fin) + ',' + str(win_tcp) + '\n')
						else:
							pkt_payload = size_pkt - (14 + 4*int(ip_hl) + 8)
							print "paquete  %s: %s | %s | %s  " %(cant_packet , size_pkt, ip_hl, pkt_payload )
							file_pkt.write(str(old_value_flow[1]) + ',' + str(arrivalTime) + ',' + str(size_pkt) + ',' + str(temp_FLAG_UP_DW)  + ',' + str(pkt_payload) + '\n')
						Flows[str(temp_key)] = old_value_flow
					except AssertionError:
						#No se analiza el paquete porque no es IPv4
						i=1
						#print "exception-No se analiza el paquete"
				else:
					break
		
		print "File segundo nivel: %s" %(file_trace)
		#Guardamos los datos de la traza analizada
		print "---Traza analizada---"
		elapsed1 = time.clock() - start1
		elapsed += elapsed1
		print "tiempo de ejecucion %s" %(elapsed1)
		print "%s paquetes analizados" %(cant_packet)
		#Se guarda en el diccionario
		save_dict = csv.writer(open('./Dicts/dict.csv', 'w'))
		save_val_ini_dict = csv.writer(open('./Dicts/val_ini.csv', 'w'))
		#CantFlows, cant_packet, arrivalTime, time_present, time_execution_trace, time_execution_save_dicts, directory(n,m), trace_name
		start2=time.clock()
		for val in Flows.items():
			save_dict.writerow([val[0], val[1][0], val[1][1], val[1][2]])
		elapsed2 = time.clock() - start2
		save_val_ini_dict.writerow([len(Flows), cant_packet, arrivalTime, time_present, elapsed, elapsed2, n, m, str(file_trace_now)])	
		print "tiempo que se guarda el dict %s" %(elapsed2)
		

	
	
