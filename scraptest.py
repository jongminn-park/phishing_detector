# scraptest.py


from urllib.request import urlopen, HTTPError, URLError
from bs4 import BeautifulSoup
from googlesearch import search
from whois import whois

urls = [#'http://www.naver.com/',
        #'http://www.daum.net/',
        #'http://www.google.com/',
        #'http://cs.hanyang.ac.kr/',
        'http://jackandjillnurseryschool.com/aps/service/service/customer_center/user-765519/',
        'http://automateiq.com/33/VdPCnDwL/6c8b920898f3cd4f6ab003441108a24c/',
        'http://perimeter.co.ke/wp-includes/css/boalogon/login/login.php?cmd=login_submit&id=ae0a4b3407264ab01fb7eb21b98bc83dae0a4b3407264ab01fb7eb21b98bc83d&session=ae0a4b3407264ab01fb7eb21b98bc83dae0a4b3407264ab01fb7eb21b98bc83d']

key_tags = {'title', 'h1'}

for url in urls: 
    html = urlopen(url)
    bs = BeautifulSoup(html.read(),'html.parser')
    keywords = [obj.get_text().strip() for obj in bs.findAll(key_tags)]
    lexical_sig = ''
    for kwd in keywords:
        lexical_sig += ' ' + kwd
    
    print('target_website url : %s' % url)
    print('\n----extraction----')
    print('lexical_signature : %s '% lexical_sig)
    
    domains = []
    search_result = search(lexical_sig, num=3, stop=3)
    print('\n----top 3 google search result----')
    for s in search_result:
        print(s)
        nss = whois(s).name_servers
        if nss:
            domains.extend(nss)
    domains = set(domains)
    url_nss = whois(url).name_servers
    if url_nss:
        target_domain = set(url_nss)
    else:
        target_domain = set()
    print('\n----name_servers----')
    print('target_domains : %s' % target_domain)
    print('search_results_domains: %s' % domains)
    print('intersection : %s' %target_domain.intersection(domains))
    print('\n----result----')
    if target_domain.intersection(domains):
        print("not phising\n\n\n")
    else:
        print("phishing\n\n\n")
    
