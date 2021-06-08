##### Uvod - osnove jezika R

# U ovom dijelu proći ćemo kroz osnove programskog jezika R. Obradit ćemo osnove
# njegove sintakse i tipove varijabli. Ovdje ćemo proći kroz neke jako bazične
# stvari. Većina "naprednijih" stvari provlačit će se kroz ostatak radionice.

##### Osnovne matematičke operacije

# Za početak, pogledat ćemo kako možemo izvršavati jednostavne naredbe direktno
# u R konzoli. Kad god u R konzolu unesemo naredbu koju R smatra valjanom te
# pritisnemo `Enter` (također poznat kao `Return`), R će u konzoli izbaciti
# rezultat izvršavanja te naredbe. Na primjer, ako u konzolu unesemo `2 + 2`, R
# će izbaciti rezultat te operacije.

2 + 2

# Isto možemo napraviti s dijeljenjem (`/`), množenjem (`*`), oduzimanjem (`-`)
# i potenciranjem (`^`).

4 / 2

2 * 3

5 - 1

3^2

# Naravno, kao i u matematici, i u R-u je potrebno paziti na grupiranje
# matematičkih izraza. `x + y / z` je (x + (y / z))

2 + 4 / 2

# `(x + y) / z` je ((x + y) / z)

(2 + 4) / 2

##### Funkcije

# Sa samim matematičkim operacijama nećemo daleko doći. R ima i *funkcije* -
# operacije koje primaju parametre (eng. *argument*) i vraćaju neke vrijednosti.
# Funkcije u R-u imaju opći oblik `funkcija(argument1, argument2, ...)`.

# Prva funkcija koju ćemo pogledati, a koja nadopunjava matematičke operacije s
# kojima smo započeli je `sqrt()`, kojom možemo dobiti korijen nekog broja.

sqrt(4)

# Druga, koja se u R-u javlja jako često, je `c()` (što je skraćeno za
# *combine*). `c()` uzima N argumenata i spaja ih u vektor.
# Na primjer, vektor brojeva možemo napraviti ovako:

c(5, 4, 3, 2, 1)

# A vektor tekstualnih elemenata (odnosno *stringova*) možemo napraviti ovako:

c('patka', "krava", 'pile', "pas")

# Navodnici su bitni! Mogu biti jednostruki ili dvostruki,
# bitno je samo da je riječ omeđena jednakim parom.
# Na primjer, 'a' je u redu, "a' nije u redu, ali zato "a" je u redu.

# Koristeći `c()`, stvorili smo dva *vektora*. Vektori spadaju među osnovne
# strukture podataka u R-u. Vektori mogu sadržavati proizvoljan broj elemenata
# istog tipa. O tipovima ćemo pričati malo kasnije. Sada ćemo se pozabaviti
# varijablama.

###### Varijable

# Kad god smo dosad izvršavali neke funkcije, baratali smo konkretnim
# vrijednostima (npr. `2 + 2`), a rezultati su ostali lebdjeti negdje u eteru.
# Kako bismo te vrijednosti negdje zabilježili, moramo ih spremiti u varijable.

# Varijablu imenujemo (eng. *declare*) tako što neki poluproizvoljan naziv
# spojimo s nekom vrijednosti, koristeći operator `<-`. Na pimjer:

a <- 2

# Ako sad u konzolu unesemo `a`, konzola će nam vratiti vrijednost te varijable.
# Isti rezultat dobili bismo ako bismo `a` iskoristili kao argument `print`
# funkcije (`print(a)`).

print(a)

# Imena varijabli *mogu* sadržavati slova, brojeve, točke (`.`) i podvlake (eng.
# *underscore*; `_`). Imena varijabli *ne mogu* započinjati točkom koju prati
# broj. R točku koju prati broj interpretira kao decimalni broj koji ispred
# decimalne točke ima nulu. Na primjer:

.3 <- 5

# .3 se ovdje tumači kao 0.3, pa je upisivanje vrijednosti 5 u 0.3 besmisleno.

# Također, imena varijabli ne mogu biti izrazi koji su rezervirani u samom
# programskom jeziku, kao što je `for` (koji se koristi za iniciranje petlji).

# Sad kad znamo kako varijablama pripisati vrijednosti, možemo spremiti vektore
# koje smo ranije napravili koristeći `c()`. Neovisno o tome što *možemo*
# koristiti svašta za imena varijabli, trebali bismo se truditi imena učiniti
# smislenima. Dugoročno, to će nas poštedjeti puno mentalnog (a nekad i
# R-ovskog) napora. Također, ako možete, izbjegavate korištenje dijakritičkih
# znakova (č, ć, ž, š, đ) u svom kodu; korištenje tih znakova može izazvati
# snažne glavobolje.

# Idemo vektor domaćih životinja spremiti u varijablu:

domace_zivotinje <- c('patka', 'krava', 'pile', 'pas')

# Isto ćemo učiniti za brojeve od 5 do 1:

brojevi.5.do.1 <- c(5, 4, 3, 2, 1)

# Kao i kad smo varijabli `a` pripisali vrijednost `2`, ni sada ne dobivamo
# nikakav output u konzoli. Ali možemo koristiti `print()` ili samo upisati ime
# varijable u konzolu kako bismo dobili njenu vrijednost.

print(domace_zivotinje)

brojevi.5.do.1

# Sad kad smo svoje vektore pripisali varijablama, možemo dohvaćati pojedine
# vrijednosti iz njih. Na primjer, ako želimo dohvatiti četvrtu vrijednost iz
# vektora `domace_zivotinje`, možemo učiniti ovo:

domace_zivotinje[4]

# `4` je, u ovom slučaju, *indeks*. U R-u indeksiranje započinje s `1`. Dakle,
# prvi element u vektoru ima indeks `1`. Za dohvaćanje trećeg elementa iz
# vektora `brojevi.5.do.1` izvršili bismo:

brojevi.5.do.1[3]

# Zadnji element, neovisno o tome koliko elemenata ima, možemo dohvatiti pomoću
# funkcije `length()`, koja vraća duljinu vektora, tj. broj elemenata koji se u
# njemu nalaze. Na primjer:

length(domace_zivotinje)

# Budući da broj elemenata ujedno označava i posljednji element, možemo učiniti
# sljedeće:

# dohvaćanje pomoću indeksa

domace_zivotinje[4]

# dohvacanje pomocu funkcije `length()`

domace_zivotinje[length(domace_zivotinje)]

# iskoristit ćemo priliku i pokazati kako možemo usporediti dvije vrijednosti

domace_zivotinje[4] == domace_zivotinje[length(domace_zivotinje)]

# Ovo funkcionira jer evaluiranje, odnosno izvršavanje koda
# `length(domace_zivotinje)` kao rezultat vraća brojku `4`.

# Također, vidjeli smo da možemo koristiti `==` kako bismo provjerili jesu li
# dva objekta, odnosno dvije varijable jednake. Na primjer

2 + 2 == 4

4 == 4

4 == 5

# Treba voditi računa o tome da su `==` i `=` *vrlo različiti*!

##### Tipovi varijabli

# R razlikuje nekoliko osnovnih tipova podataka:
# - `character` : "stringovi", tj. tekstualni podaci. Npr. `'patka'`
# - `integer` : cijeli brojevi. Npr. `1`
# - `numeric` : realni brojevi. Npr. `1.161`
# - `logical` : logičke vrijednosti. Postoje ukupno dvije - `TRUE` (može se
# kratiti u `T`) i `FALSE` (može se kratiti u `F`)
# Pogledat ćemo nekoliko primjera ovih tipova, te vidjeti kako možemo provjeriti
# kojeg je neka varijabla ili vrijednost tipa.

# Da bismo provjerili je li neka vrijednost character, koristimo `is.character()`

is.character('susjed')
is.character(domace_zivotinje[4])
is.character(1)

# Kod `integer` i `numeric` tipova postoje neke specifičnosti.
# Da bismo provjerili je li neka vrijednost integer koristimo `is.integer()`:

is.integer(1)

# Pozivanje funkcije `is.integer()` s vrijednosti `1` vraća `FALSE`. To je zato
# jer R brojeve automatski sprema kao `numeric`.

# Kako bismo natjerali R da nam da `integer` vrijednost, možemo staviti `L` na
# kraj broja:

is.integer(1L)

# Ovo je zgodno znati jer se može dogoditi da funkcija traži `integer`, ali
# odbija prihvatiti (recimo) `5` kao odgovarajuću vrijednost.

# Kako bismo provjerili je li neka vrijednost `numeric` koristimo
# `is.numeric()`:

is.numeric(1.5115)

# Za pisanje decimalnih brojeva *moramo koristiti točku* jer se zarez koristi za
# odvajanje argumenata u funkcijama.

is.numeric(1,4141)

1,5151 + 1

# Posljednji tip je `logical`:

TRUE == T
FALSE == F

is.logical(TRUE)

is.logical(F)

# Nakon upoznavanja s osnovnim tipovima vrijednosti i varijabli, pogledat ćemo
# osnovne strukture podataka.

##### Strukture podataka

# Strukture podataka su formati organiziranja, upravljanja i spremanja podataka
# koji omogućuju efikasno pristupanje podacima i njihovo modificiranje
# Već smo se upoznali s jednim tipom strukture podataka u R-u, a to je vektor. R
# ima nekoliko osnovnih struktura podataka. Ovdje ćemo proći kroz one koje se
# najčešće javljaju.

# Za ponavljanje, stvorit ćemo novi vektor:

c('vektor', 'od', '4', 'elementa')

# Možemo provjeriti je li neki objekt vektor koristeći `is.vector()`:
is.vector(c('vektor', 'od', '4', 'elementa'))

##### data.frame

# `data.frame` je vjerojatno najvažnija osnovna struktura (ili barem ona s kojom
# ćete se najčešće družiti). On odgovara onom što možemo vidjeti u *Data viewu*
# SPSS-a - sastoji se od redova koji predstavljaju jedinice analize i stupaca
# koji predstavljaju varijable. Može sadržavati varijable koje su različitih
# tipova (za razliku od nekih drugih struktura, poput vektora, koje primaju samo
# jedan tip podataka).

# `data.frame` možemo stvoriti koristeći istoimenu funkciju:

data.frame(brojke = c(1, 2, 3, 4, 5),
           'slova' = c('a', 'b', 'd', 'c', 'f'),
           'logike'= c(F, F, T, T, F))

# Pri stvaranju novog `data.framea`, svi redovi moraju imati vrijednosti na svim
# stupcima jer će se R inače požaliti.

data.frame('brojke' = c(1, 2, 3, 4, 5),
           'slova' = c('a', 'b', 'd', 'c', 'f'),
           # maknuli smo zadnjji element (F) iz stupca 'logike'
           'logike'= c(F, F, T, T))

# Tome možemo doskočiti tako što ćemo eksplicitno neku vrijednost proglasiti
# nedostajućom, što činimo pomoću posebne vrijednosti `NA`:

data.frame('brojke' = c(1, 2, 3, 4, 5),
           'slova' = c('a', 'b', 'd', 'c', 'f'),
           # umjesto posljednjeg elementa u stupcu 'logike' stavili smo NA
           'logike'= c(F, F, T, T, NA))

# Spremit ćemo ovaj data.frame u varijablu brojke_i_slova. Primijetite da smo
# sad pri definiranju vrijednosti stupca `brojke` koristili sintaksu `n:m`. Ta
# sintaksa nam daje niz brojeva između n i m.

brojke_i_slova <- data.frame('brojke' = 1:5,
                             'slova' = c('a', 'b', 'd', 'c', 'f'),
                             'logike'= c(F, F, T, T, NA))

# Sad kad smo proširili `brojke_i_slova`, pogledat ćemo kako možemo pristupati
# vrijednostima u `data.frameu`.

# Elementima možemo pristupati korištenjem uglatih zagrada, kao i kod vektora.
# Pritom treba imati na umu da je `data.frame` *dvodimenzionalni objekt*, zbog
# čega traži *dva indeksa* odvojena zarezom - *prvi* se odnosi na
# *redove*, a *drugi* na *stupce*.

# Ako jedan od indeksa izostavimo, ali stavimo zarez, R će vratiti sve elemente
# na odgovarajućem mjestu, odnosno vratit će sve redove ako izostavimo prvi
# indeks i sve stupce ako izostavimo drugi indeks.

# svi stupci prvog  reda
brojke_i_slova[1, ]

# svi redovi prvog stupca
brojke_i_slova[, 1]

# Ovdje također možemo koristiti `n:m` sintaksu za dohvaćanje raspona
# vrijednosti. Na primjer, da bismo dohvatili prva tri reda i sve stupce
# `brojki_i_slova`, napravili bismo sljedeće:

# prva tri reda, svi stupci
brojke_i_slova[1:3, ]

# Za dohvaćanje vrijednosti koje nisu uzastopne, možemo koristiti funkciju `c()`,
# koju također možemo kombinirati s `n:m` sintaksom:

# prvi red i redove 3 do 5, te stupce 1 i 3
brojke_i_slova[c(1, 3:5), c(1, 3)]

# Stupcima možemo pristupati i pomoću njihovih imena:

brojke_i_slova[1:3, c('logike', 'brojke')]

# Naposljetku, *jednom* određenom stupcu možemo pristupiti koristeći `$`
# operator:

brojke_i_slova$logike

# Prije nego što prijeđemo na sljedeću strukturu podataka, upoznat ćemo se s
# funkcijom `str()` (structure). To je funkcija koja kao input prima neki objekt
# i vraća prikaz njegove strukture. Primjerice, možemo pogledati kakva je
# struktura našeg `data.framea` `brojke_i_slova`.

str(brojke_i_slova)

# R nas informira da je `brojke_i_slova` objekt tipa `data.frame` te da sadrži
# 5 redova (`5 obs.`) i 3 varijable. Uz svaku varijablu naveden je njen tip te
# je prikazano prvih nekoliko elemenata.

# Iduća struktura podataka koju ćemo pogledata je lista.

##### list

# Lista je uređeni skup elemenata. Listu možemo definirati koristeći funkciju
# `list()`:

list('franz', 'liszt')

# Objekti u listi ne moraju biti istog tipa. Na primjer, možemo napraviti listu
# koja sadrži jedan `character`, jedan `integer` i jedan `numeric`.

spisak <- list('franz', 1L, 3.14)
spisak

# Brojevi u dvostrukim uglatim zagradama (`[[n]]`) daju nam do znanja da lista
# ima 3 elementa. To možemo potvrditi pozivom funkcije `str()` na `spisku`.

str(spisak)

# Ovdje vidimo i da `spisak` sadrži elemente različitih tipova. Liste možemo
# puniti raznolikim objektima, čak i drugim listama.

# pojedine elemente listi možemo i imenovati
raznoliki_objekti <- list(imena = c('Ramiro', 'Zorro', 'Vladimir'),
                          brojevi = c(3.61, 4.15, 7.151, 20:25),
                          inception = list(glumci = c('Leonardo di Caprio',
                                                      'ostali'),
                                           broj_kamera = 5))

str(raznoliki_objekti)

# Imenovanim elementima listi možemo pristupati isto kao i stupcima
# `data.framea`:

raznoliki_objekti$imena

raznoliki_objekti[2]

# Također, možemo dohvatiti više elemenata odjednom.

raznoliki_objekti[c('imena', 'brojevi')]

# Kad imamo ugniježđene (eng. *nested*) strukture, možemo ulančavati operatore
# za dohvaćanje kako bismo ušli dublje u strukture.

raznoliki_objekti$inception$glumci

# Posljednja struktura koju ćemo pogledati je matrica.

##### matrix

# Matrica je 2D objekt koji sadrži elemente istog tipa. Možemo je stvoriti
# koristeći funkciju `matrix()`.

postava <- matrix(c('Neo', 150, 'Morpheus', 165, 'Agent Smith', 140),
                  # broj redova matrice
                  nrow = 3,
                  # broj stupaca matrice
                  ncol = 2,
                  # trebaju li se podaci upisivati red po red ili stupac po
                  # stupac default je F
                  byrow = T)
postava

# Dimenzije matrice možemo dohvatiti funkcijom `dim`, koja je primijenjiva i na
# `data.frame` (ali ne i na liste). Funkcija nam vraca dva broja; prvi je broj
# redova, a drugi je broj stupaca.

dim(postava)

# Redovima i stupcima matrica možemo dati imena, radi lakšeg orijentiranja:

dimnames(postava) <- list(# imena redova
                          c('ozbiljni', 'pametni', 'zli'),
                          # imena stupaca
                          c('ime', 'visina'))

postava

# Imena redova možemo dohvatiti funkcijom `rownames()`, a imena stupaca
# funkcijom `colnames()`.

rownames(postava)

colnames(postava)

# Iste funkcije možemo koristiti i na `data.frameu`, pri čemu je kod njih na
# raspolaganju i funkcija `names()`.

names(brojke_i_slova)

# također, liste
names(raznoliki_objekti)

# Elementima matrice možemo pristupati pomoću `[]` operatora, ali ne i pomoću
# `$` operatora. Također, pristupanje elementima pomoću indeksa nije isto kao
# kod `data.framea`.

# Naša matrica `postava` ima 3 reda i 2 stupca. Pogledajmo sljedeći primjer:

# matrica ima manje od 4 reda i manje od 4 stupca.
# ipak, ovo funkcionira
postava[1:4]

# ovo također funkcionira
postava[2:3, 1:2]

# i ovo
postava[2:3, 'ime']

# Ovdje se imena "redova" nalaze iznad svake vraćene vrijednosti (dakle, iznad
# `"Morpheus"` i `"Agent Smith"`)

# Ovime ćemo završiti uvod u R te se baciti na pripremu podataka za obradu.
