# PKI

outes les communications dans ce projet est chiffre en utilisant l’algorithme de chiffrement symétrique AES.
- La méthode encrypt_message pour chiffre les messages.
- La méthode decrypt_message pour déchiffre les messages.

Les bibliothèques python utilise dans ce projet :

- Socket pour les communications client-serveur.
- `Cryptography` pour la création des CSR et CA.
- `Crypto` et `pyOpenSSL` pour le hash et vérification des certificats signe par CA.

# Partie 1 : signe CSR par Serveur CA


## client.py

Dans cette partie le client crée un nombre de CSR a partie de nombre de pool en entrer en paramètre.

La fonction `create_CSR` crée les CSR et les sauvegardes dans le dossier ***CSR_file*** ainsi que les
clés prives associe à chaque CSR dans le dossier **Private**.

**Example** : si le nombre de pool égale a 2, le code génère 2 CSR et 2 private key (csr_key1.csr et csr_key2.csr, private_key1.key et private_key2.key) et les sauvegardes dans CSR_file et private.

Après la création des CSR en les envois au serveur an format JSON (key : valeur) chiffre pour les signes.

```
{
key1 : CSR_key1.csr,
key2 : CSR_key1.csr,
....
}
```

Puis le client mis en attend les réponses auprès de serveur (les CSR signe ou bien les certificats).

Dès que le client reçut les certificats il les sauvegarde dans le dossier cert.

## server.py

Le serveur de son part crée une certificat root `X509 auto-signe` et le sauvegarde dans le dossier cert, après il signe les CSR reçu par le client (après le déchiffrement), puis ils envoi au client.

# Partie 2 : client 1 envoi message au client 2

Dans cette partie le client 1 envoi message au client 2 avec format (M, Signature, Certificat).

Client de son part vérifie la signature et est-ce que le certificat est signe par CA Root.

## Client1 :

Client 1 va choisir un certificat aléatoirement, puis il va signer un message par clé prive assigner au certificat choisi utilisent la fonction de hachage SHA256.

Puis envoi le message chiffre par algorithme AES au client 2.

## Client2 :

Client 2 de son part reçoit le message, puis le déchiffre. Après il vérifie le message par client public de client 1.

# Partie 3 : vérifie certificat

Dans cette partie le client 2 envoi la certificat au serveur CA pour verifie est ce que elle bien signe Root CA.
