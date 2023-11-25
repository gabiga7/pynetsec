Le programme a été fait sur un environnement windows
Il faut être en ADMINSTRATEUR pour pouvoir faire marcher le programme et que toutes les fonctionnalités marchent
Plusieurs librairies sont nécessaire au bon fonctionnement du programme.

"python3 main.py" pour lancer le programme, il prend un peu de temps à se lancer

Les points décrit ci dessous sont les différentes fonctionnalités de notre programme :

1) Une fois que l'interface graphique est lancé on clique sur "start sniffer" et on entre le nom de l'interface sur laquelle on veut voir les paquets (on la trouve via la commande IPconfig sur windows dans le cas d'un PC utilisateur une seule interface sera utilisé, Wi-Fi par exemple), on clique sur OK pour commencer l'écoute sur l'interface

2) Pour voir les paquets on clique sur "show packets counts", chaque ligne correspond à des paquets entrant et sortant, des infos sont indiqués, l'ip source, l'ip destination, le type de paquet etc.

3) Si il y a une attaque SYN FLOOD un pop up va apparaitre et ça va bloquer automatiquement l'ip

4) "Blacklist" nous permet de voir toutes les IP qui sont bloquées

5) "Block IP" et "Unblock IP" permettent de bloquer/débloquer une addresse IP

6) "Show suspicious packets" et "Clear suspicious packets" permettent voir les packets suscpicieux (des paquets potentiellement dangereux), le clear permet d'effacer à l'écran les packets

7) "analyse traffic" nous permet de voir dans un graphique les machines qui envoient/recoivent le plus de paquets avec notre machine

En conclusion notre programme permet de : Bloquer/Débloquer une IP, bloquer automatiquement les machines qui font des attaques SYN Flood sur notre machine, analyser le traffic passant par l'interface sur laquelle on écoute, afficher le traffic


