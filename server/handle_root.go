package server

import "github.com/labstack/echo/v4"

func (s *Server) handleRoot(e echo.Context) error {
	return e.String(200, `

                                 ....-*%%%##### 
                     .%#+++****#%%%%%%%%%#+:....
            .%+++**++++*%%%%.....               
     .%+++*****#%%%%#.. %#%...                  
 ***+*****%%%%%...       =..                    
 *****%%%%..            +=++..                  
 %%%%%...             .+----==++.               
                     .-::----===++              
                   .=-:.------==+++             
                   +-:::-:----===++..           
                   =-::-----:-==+++-.           
                  .==*=------==++++.            
                  +-:--=++===*=--++.            
                  +:::--:=++=----=+..           
                  *::::---=+#----=+.            
                  =::::----=+#---=+..           
                  .::::----==+=--=+..           
                  .-::-----==++=-=+..           
                   -::-----==++===+..           
                   =::-----==++==++             
                   +::----:==++=+++             
                   :-:----:==+++++.             
                   .=:=----=+++++.              
                    +=-=====+++..               
                     =====++.                   
                      =++...                    


This is an AT Protocol Personal Data Server (aka, an atproto PDS)

Code: https://github.com/haileyok/cocoon
Version: `+s.config.Version+"\n")
}
