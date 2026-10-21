<?php
// Fichier de configuration — jamais accessible directement via le web (voir .htaccess).
// Ne pas committer ce fichier dans un dépôt public.

declare(strict_types=1);

return [
    // Connexion à la base de données MySQL (sur le même serveur que l'hébergement).
    'db' => [
        'host' => '127.0.0.1',
        'port' => 3306,
        'name' => 'u398941569_facturation',
        'user' => 'u398941569_facturation',
        'pass' => 'JGeETh7MOeksy59dUrza',
    ],

    // Hash (bcrypt) du mot de passe d'accès à l'application.
    // Le mot de passe en clair n'est jamais stocké.
    'app_password_hash' => '$2y$10$SGnpX49Nb.WvaxPhPDBOhub.pMyJPODHr6m8CXCpUkzTKXwtsxBvm',
];
