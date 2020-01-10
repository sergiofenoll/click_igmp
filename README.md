# Project Telecommunicatiesystemen 2019-2020

# Gebruik

De mappen 'elements' en 'scripts' moeten op hun respectievelijke locaties in de click directory geplaatst worden, analoog aan de voorbeeldimplementatie. 

## Handlers

Er zijn twee handlers beschikbaar voor de Clients:

* client/igmp.join [ADDRESS] 
Met deze handler kan de client interesse tonen in de opgegeven multicast groep. 

* client/igmp.leave [ADDRESS]
Deze handler kan gebruikt worden om interesse in een groep op te heffen.

Deze handlers werken analoog aan die uit de voorbeeldimplementatie. 


## Elementconfiguratie

Zowel in de Router als in de Clients zijn er elementen toegevoegd om IGMP te ondersteunen. De primaire elementen kunnen a.d.h.v. parameters geconfigureerd worden. Zie RFC 3376, Sectie 8 voor details en betekenis van de parameters. De default waarden van de optionele parameters zijn overgenomen uit de RFC.

### IGMPResponder
Het Client-side IGMP element. Accepteert de volgende optionele parameters:

* URI -  Unsolicited Report Interval (in seconden)

## IGMPQuerier
Het Router-side IGMP element. Accepteert de volgende optionele parameters:

* RV - Robustness Variable
* QI - Querier interval (in seconden)
* QRI - Querier Response Interval (in seconden)
* LMQI - Last Member Query Interval (in seconden)
* SQI - Startup Query Interval (in seconden)
* SQC - Startup Query Count
* LMQC - Last Member Query Count

