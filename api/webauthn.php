<?php
declare(strict_types=1);

// Fonctions utilitaires pour l'authentification WebAuthn (empreinte digitale /
// Face ID). Pas de bibliothèque externe : tout est écrit ici volontairement
// en PHP standard (openssl + un petit décodeur CBOR maison), pour ne
// dépendre d'aucun gestionnaire de paquets côté hébergement.

const WA_RP_ID = 'facturation.steedsolutionsexterieurs.fr';
const WA_ORIGIN = 'https://facturation.steedsolutionsexterieurs.fr';

function b64u_encode(string $data): string
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function b64u_decode(string $data): string
{
    $data = strtr($data, '-_', '+/');
    $pad = strlen($data) % 4;
    if ($pad) {
        $data .= str_repeat('=', 4 - $pad);
    }
    $out = base64_decode($data, true);
    return $out === false ? '' : $out;
}

// --- Décodeur CBOR minimal, suffisant pour les objets renvoyés par WebAuthn
//     (entiers, chaînes, tableaux, tables - pas de date/tag/flottant). ---
function cbor_decode(string $buf, int &$off)
{
    $byte = ord($buf[$off]);
    $major = $byte >> 5;
    $info = $byte & 0x1f;
    $off++;
    $len = cbor_read_len($buf, $off, $info);

    switch ($major) {
        case 0: // entier non signé
            return $len;
        case 1: // entier négatif
            return -1 - $len;
        case 2: // chaîne d'octets
            $v = substr($buf, $off, (int)$len);
            $off += (int)$len;
            return $v;
        case 3: // chaîne de texte
            $v = substr($buf, $off, (int)$len);
            $off += (int)$len;
            return $v;
        case 4: // tableau
            $arr = [];
            for ($i = 0; $i < $len; $i++) {
                $arr[] = cbor_decode($buf, $off);
            }
            return $arr;
        case 5: // table (map)
            $map = [];
            for ($i = 0; $i < $len; $i++) {
                $k = cbor_decode($buf, $off);
                $v = cbor_decode($buf, $off);
                $map[$k] = $v;
            }
            return $map;
        case 7: // simple / booléen / null
            if ($info === 20) {
                return false;
            }
            if ($info === 21) {
                return true;
            }
            return null;
        default:
            return null;
    }
}

function cbor_read_len(string $buf, int &$off, int $info)
{
    if ($info < 24) {
        return $info;
    }
    if ($info === 24) {
        $v = ord($buf[$off]);
        $off += 1;
        return $v;
    }
    if ($info === 25) {
        $v = unpack('n', substr($buf, $off, 2))[1];
        $off += 2;
        return $v;
    }
    if ($info === 26) {
        $v = unpack('N', substr($buf, $off, 4))[1];
        $off += 4;
        return $v;
    }
    if ($info === 27) {
        $hi = unpack('N', substr($buf, $off, 4))[1];
        $lo = unpack('N', substr($buf, $off + 4, 4))[1];
        $off += 8;
        return $hi * 4294967296 + $lo;
    }
    return 0;
}

// Construit une clé publique PEM à partir d'une clé COSE EC2 / P-256 (ES256),
// le format utilisé par la quasi-totalité des capteurs d'empreinte / Face ID
// sur mobile. Clés CBOR : 1=kty, 3=alg, -1=crv, -2=x, -3=y.
function cose_ec2_to_pem(array $cose): ?string
{
    if (($cose[1] ?? null) !== 2) {
        return null; // kty doit être EC2
    }
    if (($cose[-1] ?? null) !== 1) {
        return null; // courbe P-256 uniquement
    }
    $x = $cose[-2] ?? null;
    $y = $cose[-3] ?? null;
    if (!is_string($x) || !is_string($y) || strlen($x) !== 32 || strlen($y) !== 32) {
        return null;
    }
    // Préfixe DER fixe (SubjectPublicKeyInfo) pour une clé EC P-256 non compressée.
    $prefix = hex2bin('3059301306072a8648ce3d020106082a8648ce3d03010703420004');
    $der = $prefix . $x . $y;
    return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
}

// Analyse le champ "authenticatorData" renvoyé lors d'un enregistrement
// (navigator.credentials.create) pour en extraire l'identifiant et la clé
// publique du nouvel appareil.
function parse_auth_data(string $authData): array
{
    $rpIdHash = substr($authData, 0, 32);
    $flags = ord($authData[32] ?? "\x00");
    $signCountArr = unpack('N', substr($authData, 33, 4));
    $signCount = $signCountArr ? $signCountArr[1] : 0;
    $off = 37;

    $result = [
        'rpIdHash' => $rpIdHash,
        'flags' => $flags,
        'signCount' => $signCount,
        'credentialId' => null,
        'cosePublicKey' => null,
    ];

    if ($flags & 0x40) { // AT : données de l'identifiant attesté présentes
        $off += 16; // aaguid, non utilisé
        $credIdLenArr = unpack('n', substr($authData, $off, 2));
        $credIdLen = $credIdLenArr ? $credIdLenArr[1] : 0;
        $off += 2;
        $credId = substr($authData, $off, $credIdLen);
        $off += $credIdLen;
        $cose = cbor_decode($authData, $off);
        $result['credentialId'] = $credId;
        $result['cosePublicKey'] = $cose;
    }

    return $result;
}
