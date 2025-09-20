Erstelle eine Timeline Anwendung. Die Anwendung soll im Backend rust nutzen, für das frontend einen Webserver mit HTML/CSS/JS und für die Daten eine PostgreSQL Datenbank. Alles davon soll in Docker laufen, damit es besser Organisiert ist und die Umgebung auf jedem System gleich ist.

Die Aktuellen Tags auf Dockerhub sind:
- Rust: "rust:1.89.0-trixie"
- Debian: "debian:trixie-slim"
- PostgreSQL: "postgres:13-trixie"

Debian 13 "trixie" ist mittlerweile die neuste Stable Version von Debian.
Nutze die oben genannten Images von Dockerhub, um Fehler zu vermeiden.

----------

Die Anwendung soll mit einem einzigen Docker Compose Befehl gestartet werden können.
Das setup der Anwendung muss so sein und darf nicht anders sein:
```
git clone [repository url]
cd timeline
sudo docker compose up -d
```
Danach soll im selben verzeichniss in dem die "docker-compose.yml" ist, eine admin_credentials.txt sein, in der die die Zuangsdaten stehen. Die Zugangsdaten sind "admin" und ein zufällig generiertes 32 Zeichen langes Passwort.

----------

Alles soll über eine Adresse Laufen. Nehmen wir an, die Adresse ist "https://example.com/".
Dann soll unangemeldeten Nutzern auf "https://example.com/" eine Anmeldeseite gezeigt werden.
Wenn man als Admin angemeldet ist wird einem auf "https://example.com/" das Admin Dashboard gezeigt.
Wenn man als Nutzer angemeldet ist wird einem auf "https://example.com/" die Nutzeroberfläche gezeigt.
Und so weiter. Alles läuft über eine URL.

----------

Der Admin Nutzer hat keine normale Ansicht auf die Anwendung sondern sieht immer nur ein Dashboard. Auf dem Dashboard kann er folgendes machen:
- Sich Abmelden
- Sein Passwort ändern.
- Nutzer verwalten:
  -> Nutzer hinzufügen. (Nutzername auswählen und es wird ein Account erstellt und ein Zufälliges 32 Zeichen langes Passwort einmalig gezeigt. Es ist vorgesehen, dass der Nutzer das Passwort dann ändert, damit der Admin es nichtmehr weiß.)
  -> Nutzer Löschen. (Der Admin muss erstens einem Löschen knopf drücken, dann zweitens Bestätigen dass er den Nutzer löschen möchte, dann drittens den Namen des Nutzers eingeben um sicherzustellen, dass er den richtigen Nutzer löschen möchte und dann viertens nochmal bestätigen. Versehentliches löschen soll nicht möglich sein.)

----------

Es soll eine Timeline Anwendung werden, das Bedeutet es soll eine Anwendung werden in der Nutzer ihre erfahrungen Notieren können. Das muss natürlich Privat sein.
Nutzerpasswörter sollen nur gehasht gespeichert werden und Nutzerdaten sollen nur verschlüsselt gespeichert werden. Es sollen nie Daten unverschlüsselt auf die Festplatte gelangen.
Nutzerdaten sollen nach dem Zero-Knowledge konzept gespeichert werden und nur der jeweilige Nutzer soll sie entschlüsseln können. Beachte dabei, dass die Nutzerdaten nach einer Passwortänderung des Nutzers, immernoch für diesen entschlüsselbar sein müssen.
Nutzeranmeldungen sollen mit Cookies im Browser gespeichert werden. Die gültigkeit der Cookies muss im Backend verifiziert werden. Ob ein Cookie gültig ist soll nie auf die Backend Festplatte gespeichert werden, sondern immer nur im RAM gehalten werden. Bei einem neustart des Backend werden alle Nutzer dadurch Abgemeldet.
wenn ein Nutzer sich Abmeldet soll der Cookie seiner Anmeldung im Backend ungültig gemacht werden, damit er wirklich abgemeldet ist.

Da die Daten Zero-Knowledge verschlüsselt werden und nur im Frontend entschlüsselt sind, kann man kurze wege über http gehen um es zu vereinfachen. Der Server bekommt in Production eine Reverse Proxy vor sich, welche https (SSL) ermöglicht. Der Server muss selber keine Zertifikate unterstützen.

----------

Das UI soll generell sehr einfach gehalten sein.
Die Seite selber soll immer so groß sein wie das Display und man soll nicht die seite scrollen können. Wenn etwas zu scrollen ist, ist es immer in Boxen, die gescrollt werden können, aber niemals ist die ganze seite zum scrollen.
Die Akzentfarbe ist: #710193
Es soll einen Lightmode und einen Darkmode geben. Welcher Modus verwendt wird soll in den Nutzereinstellungen eingestellt werden können. Es soll die Möglichkeiten "Light", "Dark" und "Device" geben. Device wählt den Modus nach den Geräteeinstellungen und ist standart.
Alle Nutzereinstellungen sollen (auch verschlüsselt) im Backend gespeichert werden, damit ein Nuter auf jedem Gerät auf dem er Angemeldet ist, immer seine Einstellungen hat.
Die Komplette Anwendung soll dem Nutzer auf Englisch (UK) Präsentiert werden.
Es gibt keine Javascript Popups in denen "Ja/Nein" oder ein Text abgefragt wird. Alle eingabefenster sind als Overlay selber im UI erstellt und angepasst Designt.
Nutze im UI keine Emojis.

Nutze für alles ein Design. Halte das Design der Anwendung einheitlich.
Schreibe das UI komplett in HTML/CSS/JS selber und nutze keine unnötigen externen Design bibliotheken.
----------

Die Eigentliche Anwendung soll eine Seite mit Vertikaler Timeline sein. Links ist eine Leiste (vertikaler strich) welche die Timeline Darstellt. Objekte auf der Timeline werden dargestellt inden auf der Leiste ein Punkt ist. Rechts neben dem Punkt ist ein Kasten. In dem Kasten sind Daten zu diesm Ereigniss auf der Timeline.
Daten welche in dem Kasten stehen sind:
- Titel (kurz: was ist passiert) (wird Fett oben-links im kasten angezeigt)
- Zeitpunkt (wann ist das passiert. Uhrzeit und Datum. HH:MM:SS DD:MM:YYYY) (wird in einem kleineren kasten mit einer leicht anderen Farbe oben-rechts im kasten angezeigt)
- Beschreibung (was ist passiert. Ausführlicher) (wird unter dem Titel links-orientiert im kasten angezeigt)
- Timer (wie lange her ist das. Zeigt an "XX Years XX Months XX Days XX Hours XX Minutes XX Seconds ago". Die Zahlen sind dabei fett und etwas größer als sie wörter. Es ist ein Timer, welcher Live die Zeit anzeigt, welche vom Zeitpunkt bis jetzt vergangen ist.) (Wird links-orientiert unter der beschreibung angezeigt)
- Tags (sind optionale filter/hashtags, welche einem Event zugeordnet werden können. Sie werden nebeneinander als kleine bunte (akzentfarbe) kästen angezeigt, welche abgerundete acken haben.) (werden links-orientiert unter dem Timer angezeigt)
- Event Löschen (Knopf, welcher das jeweilige Event aus der Timeline Löscht. Um ein event zu löschen muss man erstens den löschen-knopf drücken, zweitens den namen des events zur bestätigung eingeben und drittens das löschen bestätigen. Es soll nicht möglich sein, versehentlich ein event zu löschen.) (wird rechts-unten im kasten angezeigt)

Durch diese Vertikale Timeline kann gescrollt werden.
Oben Ist eine Dauerhaft sichtbare leiste, welche nicht weggescrollt werden kann. Unten ist auch eine Dauerhaft sichtbare leiste welche nicht weggescrollt werden kann.
In der Oberen Leiste ist Folgendes:
- Anzahl der Events ("[Anzahl] Events in the list". Ist ein kleicher kasten mit abgerundeten ecken der durch diesen Text die Anzahl der Events Zeigt, welche insgesamt in der liste sind.) (ganz links in der leiste)
- Burgermenü (Ein "Bürgermenü"/"Drei stricher menü", mit welchem  man einen kleinen kasten aus-/ein-klappen kann in den die Optionen "Settings", "Backuo" und "Sign Out" sind.) (ganz rechts in der leiste)
  -> Settings (öffnet ein Overlay mit einstellungen. Diese sind änderung des Anzeigenamens, welcher separat vom login namen geregelt wird. Passwortänderungen mit "old password", "new password" und "confirm new passwort" feldern. Design änderung mit "Light", "Dark" und "System". Zeit einstellungen für die Darstellung von Zeit im UI, nach "24H" oder "AM/PM". Datums einstellungen welche einstellen wie das Datum im UI dargestellt wird (mit gültigen datumsformaten). Ein "Save" knopf unter jede der einstellungen (der "change password" knopf gilt schon als save knopf, sodass es für passwort änderungen keinen zweiten save knopf braucht)) (wird als Overlay über die Anwendung gelegt. Das Overlay kann mit einem X oben-rechts geschlossen werden, wobei ungespeicherte änderungen verlorengehen.)
  -> Backup (Ein overlay mit den Backup Optionen. Diese sind "export", wobei alle events der Timeline als JSON Datei unverschlüsselt heruntergeladen werden können. Und "import" wo man eine solche JSON Datei hochladen kann, dabei werden die Aktuellen Daten nicht ersetzt, sondern durch die Daten in der JSON Datei ergänzt. Die entschlüsselung und verschlüsselung findet komplett im frontend statt. Daten aus der JSON gelangen niemals unverschlüsselt an den server.) (wird als Overlay über die Anwendung gelegt. Das Overlay kann mit einem X oben-rechts geschlossen werden.)
  -> Logout (Man wird abgemeldet) (Nach der abmeldung wird die seite neu geladen, sodass man wieder die einlogg seite sieht.)

In der Unteren Leiste ist Folgendes:
- Event Hinzufügen (öffnet ein overlay zum hinzufügen eines events. Im overlay kann man Titel, Beschreibung, Zeitpunkt und Tags eingeben und dann das event erstellen) (Länglicher knopf mit abgerundeten ecken. Mittig in der leiste. Das overlay kann mit einem X wieder geschlossen werden oder schließt sich, wenn man das event erstellt hat.)
  -> Titel Pflichtfeld (eingabefeld für den Titel des Events) (ganz oben im overlay)
  -> Beschreibung Pflichtfeld (Einganefeld für die Beschreibung des Events) (Unter dem Titel Feld)
  -> Zeitpunkt Pflichtfeld (Schalter, welcher auf "Now" steht um die aktuelle zeit zu wählen. Man kann den schalter auf "Custom" stellen um 6 Zahlen-Eingabefelder anzuzeigen, in denen man jeweils Tag, Monat, Jahr, Stunde, Minute und Sekunde einstellen kann. Dann wird diese Zeit genutzt.) (Unter dem Beschreibungs Feld.)
  -> Tags Optionales-Feld (checkliste von Tags die es gibt. Man kann Bereits existierende Tags Anwählen oder neue Tags mit einem eingabefeld erstellen.) (Unter den Zeitpunkt Feldern)
  -> Erstellen Knopf (Knopf zum Erstellen des Events) (Unter dem Tag Menü)
- Nach events suchen (Suchleiste mit der man nach events suchen kann. Es wird in den Beschreibungen und Titeln aller Events nach der eingabe gesucht und nach diesen events gefiltert. Die Suche findet im frontend statt.) (Ganz links in der Leiste. Suchleiste mit abgerundeten ecken. "Suchen" Knopf Rechts in der Suchleiste. Statt dem "Suchen" Knopf kann man auch Enter drücken während man in der Suchleiste schreibt.)
- Tag Filter (Möglichkeit events zu suchen, welche bestimmte Tags haben.) (Rechts neben der Suchleiste)
  -> Funktioniert wie ein Burgermenü. Man kann es zum ausklappen und einklappen eines kleinen Fensters nutzen, welches alle verfügbaren Tags in einer Auswahlliste Zeigt. Man wählt Tags aus und es werden nurnoch Events gezeigt, welche alls Ausgewählten Tags haben.
- Anzahl der Gefilterten Events ("[Anzahl] Events". Ist ein kleicher kasten mit abgerundeten ecken der durch diesen Text die Anzahl der Events Zeigt, welche aktuell angezeigt werden, also den aktuellen filtern entsprechen.) (ganz rechts in der leiste)

Tags organisieren sich zum Teil selber. Man kann Tags erstellen, wenn man ein neues Event erstellt. Beim erstellen eines neuen Events kann man auch bestehende Tags anwählen. Wenn es keine Events mehr gibt, welche ein bestimmtes Tag haben, so hat dieses Tag keine Events mehr und wird auch gelöscht. Tags können als Filter und Suchmöglichkeit genutzt werden.

Events werden nach Zeitpunkt sortiert geordnet. Ältere Events sind weiter oben und neuere Events wieter unten. Wenn man die Seite lädt oder die Filter Aktualisiert, wird man wieder an das untere ende der Liste getan, also zu den neueren Events.

----------

Falls du Symbole als Bilddatei für das UI brauchst, erstelle mir in der README.md eine Markdown Tabelle, die in einer spalte das jeweilige Symbol beschreibt und in der anderen spalte den Pfad angibt, in den ich es legen soll. Ich werde die Symbole dann als PNG Datei in die jeweiligen pfade legen.
Nutze KEINE Emojis als Symbole.

----------

Teste die anwendung bevor du die Pull Request einreichst. Bedenke, dass es nichts nützt die Frontend HTML im Browser zu öffnen und du gezwungen bist wirklich das Backend zu starten und die localhost adresse des Webservers aufzurufen.
Reiche die Pull Request erst ein, wenn alles Funktioniert. Achte auch darauf, dass optisch nichts verschoben ist und alles passt.

----------

Halte dich genau an diesen Plan. Erstelle nun diese Anwendung.
Mache alles auf Englisch (UK).
