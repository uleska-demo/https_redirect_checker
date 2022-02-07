import requests
import sys
import argparse
from uleska.vulnerability import Vulnerability, Severity
from uleska.formatter import save_vulns_to_file


def _print_logo():
    print('''
========================================================================================================================

Simple HTTPS Check

========================================================================================================================
''')


def _main():

    # Logo
    _print_logo()



    ###########################
    ##  Collect Scan Args   ###
    ###########################
    
    #Capture command line arguments
    arguments = sys.argv
    
    # variables to be used during processing
    issues_found = []

    ##
    
    print ("############ Scan Parameters ############")
    
    arg_options = argparse.ArgumentParser(description="Runs a simple HTTPS redirection test")
    arg_options.add_argument('--url', type=str)
    arg_options.add_argument('--debug', type=str)
    arg_options.add_argument('--output', type=str)

    url = ""
    debug = False
    output = ""

    args = arg_options.parse_args()
    
    #Grab the startURL
    if args.url is not None:
        url = args.url
        print("URL: " + url)
        
    #Grab the startURL
    if args.debug is not None:
        if args.debug == "true":
            debug = True
        print("Debug: " + str(debug))
    
    #Grab the location for the output xml file
    if args.output is not None:
        vulns_output_location = args.output
        print("Output is: " + vulns_output_location)




    print ("#########################################\n")

    #Requests
    s = requests.Session()

    url_to_use = url.replace('https', 'http')

    print(f"Accessing {url_to_use} \n")
    
    Response = s.request("Get", url_to_use, allow_redirects=False)
    
    code = Response.status_code

    if code == 300 or code == 301 or code == 302 or code == 303 or code == 304 or code == 307 or code == 308:
        
        print(f"Successfully received a redirect {code} for {url_to_use} \n")
    
    else:

        # We have not received a redirect
        print(f"Failed to receive a redirect for {url_to_use}, instead received {code}, raising issue...\n")

        # Raise the issue
        vuln = Vulnerability (title="No HTTP redirect to HTTPS",
                              summary="HTTP access to site does not redirect to an HTTPS location",
                              explanation="In testing, when a request for the HTTP protocol for the site was made, there was not a redirect for the HTTPS location",
                              recommendation="Update the server configuration to ensure non-secure requests for these pages result in a redirect.",
                              source=url_to_use,
                              severity=Severity.HIGH,
                              cvss='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
                              md5="a9f54e2a88ede11530aa9d914fe2bbcc" )
        
        issues_found.append( vuln )
        
        if debug:
            print ("\n######################### DEBUG #################################")
            print ("Issue added to list: Title [" + vuln.title + "], Summary [" + vuln.summary + "]")
            print ("###################################################################\n\n")

        


    # Save the vulnerabilities to the XML file
    save_vulns_to_file(issues_found, vulns_output_location, '1.2')

if __name__ == '__main__':
    _main()