##! T1172_domain_front.zeek (Command & Control)
##! https://attack.mitre.org/techniques/T1172/
##! Mike McPhee - SANS Research Topic #1
##! 


@load base/protocols/conn
@load base/protocols/ssl
@load base/frameworks/notice
@load base/protocols/http/main


##! Will ID SSL connections and determine the SNI matches the HTTP host
event connection_state_remove(c: connection) {
    
    ##! Filter out non-SSL/TLS noise looking for presence of appropriate ssh information
    if ( c?$ssl == F ) {
        return;
    }    

    ##! For every connection id associated with a SSL/TLS session, check bonafides 
        }
    ##! If an SSH session has a ton of bytes, takes too long, or looks too big, it probably is - send an alert and log it!
    if ( (c?$ssl == T) && ((c$http$host != hostc$ssl$server_name)) {
        
        ##! Print out alert to terminal
        print fmt ("[WARNING] Potential Domain Fronting Detected (ATT&CK T1172)");
        print fmt ("Time: %s Client: %s Server: %s SNI: %s Host: %s Connection: %s", strftime("%Y/%M/%d %H:%m:%S", c$conn$ts), c$id$orig_h, c$id$resp_h, c$ssl$server_name, c$http$host, c$uid ); 
            
        ##! And capture for posterity in notice.log
		NOTICE([
                $note = Weird::Activity, 
				$msg = "Potential Domain Fronting Detected (ATT&CK T1172)",
				$conn = c
        ]);
        }
    }

