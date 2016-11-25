#!/usr/bin/python

# -------------------------------------------------------------------------------------------------------------------------- #
#                     .g8888bgd 
#                   .dP       M 
# ,pP"Ybd  ,pW8Wq.  dM        ; 
# 8I      6W     Wb MM          
#  YMMMa. 8M     M8 MM.         
# L.   I8 YA.   ,A9  Mb.     , 
# M9mmmP;  .Ybmd9.    ..bmmmd.
# -------------------------------------------------------------------------------------------------------------------------- #

import sys	
sys.path.append('core')
from imports import *
from functions import *

# --------------------------------------------------------------------------------------------------- #
def main():
	try:	
		def main_menu():
			banner()
			while True:
# --------------------------------------------------------------------------------------------------- #
# --------------------------- Main Menu ------------------------------------------------------------- #			
				main_menu_option = raw_input("\033[1;36m:: > \033[1;m")
# --------------------------------------------------------------------------------------------------- #
# -------------------- Main Menu -------------------------------------------------------------------- #			
				while main_menu_option == "1":
					menu1sub1()
					repo = raw_input("\033[1;32mWhat do you want to do ?> \033[1;m")
					if repo == "1":
						do_track()
						
					elif repo == "2":
						do_wifiscan()
					elif repo == "3":
						do_proximity()
					elif repo == "4":
						exit()
					elif repo == "back":
						os.system("clear")
						help_menu()
					elif repo == "gohome":
						os.system("clear")
						main_menu()
					elif repo == "exit":
						exit()
					else:
						com_error()					
						

				if main_menu_option == "3":
					menu_people()

				elif main_menu_option == "4":
					os.system("clear")
					exit()

				elif main_menu_option == "exit":
					os.system("clear")
					exit()
				elif main_menu_option == "help":
					help_menu()

				else:
					com_error()

				def menu_2():
					
					while main_menu_option == "2":
						menu_2_banner()
						print ("\033[1;32mSelect a category.\n\033[1;m")

						menu_2_option = raw_input("\033[1;36m:: > \033[1;m")
						if menu_2_option == "back":
							main_menu()
						elif menu_2_option == "gohome":
							main_menu()
						else:
							com_error()
# --------------------------------------------------------------------------------------------------- #
# --------------------- Bluetooth Module Menu ------------------------------------------------------- #
# --------------------------------------------------------------------------------------------------- #
					
						while menu_2_option == "1":
							os.system("clear")
							bluetooth_scan_banner()
							print ("\033[1;32mWhich Module would you like.\n\033[1;m")
							opcion2 = raw_input("\033[1;36m:: > \033[1;m")
							if opcion2 == "1": # -------- calls the bluetooth scanner --------------- #
								btscanner() # ------------------------------------------------------- #
							elif opcion2 == "back":
								help_menu()
							elif opcion2 == "gohome":
								main_menu()		
											
							else:
								com_error()
# --------------------------------------------------------------------------------------------------- #
				def menu_people():
					while main_menu_option == "3":
						os.system("clear")
						People_module()
						print ("\033[1;32mWhich Module would you like.\n\033[1;m")
						opcion3 = raw_input("\033[1;36m:: > \033[1;m")
						if opcion3 == "1":
							do_shake() # ------------------------------------------------------- #
							time.sleep(5)
						elif opcion3 == "2":
							do_meet()
							time.sleep(5)
						elif opcion3 == "back":
							help_menu()
						elif opcion3 == "gohome":
							main_menu()		
										
						else:
							com_error()
# --------------------------------------------------------------------------------------------------- #					
				menu_2()
		main_menu()
# --------------------------------------------------------------------------------------------------- #
	except KeyboardInterrupt:
		print ("Shutdown requested...Goodbye...")
	except Exception:
		traceback.print_exc(file=sys.stdout)
	sys.exit(0)

if __name__ == "__main__":
    main()
# --------------------------------------------------------------------------------------------------- #