##### Rdionica: priprema datoteke `podaci_upitnik` za obradu

# U ovom dijelu radionice koristit ćemo neke dodatne pakete, koje je potrebno
# posebno instalirati i učitati. Pakete možete instalirati izvršavanjem naredbe
# ispod:

install.packages(c('tidyverse',
                   'here',
                   'haven',
                   'readxl'))

# U ovom dijelu radionice proći ćemo put od sirovih podataka do podataka na
# kojima možemo provesti analizu.

# Prije nego što se bacimo na učitavanje i proučavanje sirovih podataka, učitat
# ćemo pakete koje ćemo koristiti. Pakete učitavamo pozivanjem funkcije
# `library()`, koja kao argument prima ime *jednog* paketa.

# skupina paketa koja sadrži većinu paketa koje
# ćemo koristiti za baratanje podacima
library(tidyverse)

# omogućava učitavanje .SAV fielova
library(haven)

# omogućava učitavanje .xlsx fielova
library(readxl)

# olakšava korištenje relativnih file pathova
library(here)

##### Učitavanje podatka

# Za početak, pogledat ćemo kako izgledaju naši sirovi podaci. A da bismo to
# učinili, prvo ih moramo učitati u R. Vidjet ćemo kako učitati tri vrste
# datoteka: SPSS-ov `.sav`, Excelov `.xls/xlsx` te generički *comma separated
# values* file - `.csv`.

##### SPSS - .sav

# `.sav` datoteke možemo učitati koristeći funkciju `read_sav()` iz paketa
# `haven`. Funkcija kao argument prima samo put do datoteke koju želimo učitati.

podaci_spss <- read_sav(here('podaci', 'podaci_upitnik.sav'))

# Funkcija `here()` konstruira relativni put do datoteke `podaci_upitnik.sav`,
# koji kreće od *root* foldera, a koji je označen prisustvom prazne datoteke
# imena `.here`.

# To je jedan od načina koji osigurava reproducibilnost obrada pri prijenosu
# koda s jednog računala na drugo i lišava nas muke ručnog mijenjanja puteva do
# datoteka. Isto postižemo stvaranjem projekta u RStudiju. Osim na datoteku
# `.here`, funkcija `here()` reagira i na datoteke sa sufiksom `.Rproj` (koje
# nastaju pri stvaranju RStudio projekta).

# Ako pogledamo sadržaj varijable `podaci_spss`, vidjet ćemo da nismo dobili
# `data.frame`, nego `tibble`.

podaci_spss

# `tibble` je struktura jako slična `data.frameu`. Jedna lako uočljiva razlika
# je to što je output koji dobijemo kad ispišemo vrijednost `tibblea`
# kompaktniji od onog koji bismo dobili kad bismo ispisali `data.frame`.

as.data.frame(podaci_spss)

# Simpatična funkcija koju možemo koristiti za pregledavanje `tibbleova` (ali i
# `data.frameova`) je `glimpse()`:

glimpse(podaci_spss)

# Koristeći funkciju `head()` (`tail()`) možemo pogledati, po defaultu, prvih
# (posljednjih) 6 redova tablice. Ove funkcije pomažu nam pri pregledavanju
# strukture podataka i njihovih sirovih vrijednosti.

head(podaci_spss)

tail(podaci_spss, 3)

##### Excel - .xls(x)

# Podatke u `.xlsx` (`.xls`) formatu možemo lako učitati pomoću funkcije
# `read_xlsx()` (`read_xls()`) iz paketa `readxl`. `readxl` moramo posebno
# učitati, što smo i učinili ranije.

podaci_eksl <- read_xlsx(path = here('podaci', 'podaci_upitnik.xlsx'))

glimpse(podaci_eksl)

##### Comma separated values - .csv

# *Comma separeted value* datoteke su točno to što ime kaže - podaci koji su
# strukturirani kao vrijednosti odvojene zarezima, gdje se svaki unos (na
# primjer sudionik) nalazi u zasebnom redu, a vrijednosti varijabli koje su uz
# njega povezane ispisane su redom i odvojene su zarezima.

# U prvom redu (koji funkcije u R-u često nazivaju *header*) obično se nalaze
# imena varijabli, a u ostalim redovima su njihove vrijednosti.

# Ovako izgledaju prva dva reda i prvih nekoliko stupaca datoteke
# `podaci_upitnik.csv`:
#
# attitudesAndNorms01,attitudesAndNorms02,attitudesAndNorms03, ...
# 5,5,5,5,4, ...

# Podatke u `.csv` formatu možemo učitati pomoću funkcije `read_csv()` iz
# `readr` paketa (koji je automatski učitan kad smo učitali `tidyverse`).
# Osnovni (base) R ima funkciju `read.csv()` koja obavlja isti zadatak, ali neki
# R developeri preporučuju korištenje `read_csv()` funkcije (na primjer, Hadley
# Wickham i Garret Grolemund: http://r4ds.had.co.nz/import.html).

# U skladu s tom preporukom, koristit ćemo `read_csv()`. Podatke iz datoteke
# `podaci_upitnik.csv` možemo učitati ovako:

podaci <- read_csv(here('podaci', 'podaci_upitnik.csv'))

# Poruka koju dobivamo obavještava nas o tome kako su određene varijable
# reprezentirane. Vidimo da su varijable koje počinju s `pi` reprezentirane kao
# `character`. Ako pozovemo funkciju `spec`, vidjet ćemo specifikacije svih
# varijabli.

# Budući da pozivanjem funkcije `glimpse()` zapravo dobivamo manje-više iste
# podatke, pozvat ćemo samo nju. Njen output pomoći će nam da vidimo jesu li
# podaci reprezentirani onako kako bismo očekivali.

glimpse(podaci)

# Osnovnu deskriptivnu statistiku možemo dobiti pomoću generičke funkcije
# `summary()`. Generičke funkcije primaju objekte različitih tipova, a njihov
# output ovisi o tipu objekta. Primjerice, ako u `summary()` stavimo `data.frame`,
# dobit ćemo grubu deskriptivnu statistiku njegovih stupaca. Ako u funkciju
# stavimo regresijski model, dobit ćemo informacije o modelu.

# Idemo vidjeti output tih dviju funkcija kad u nju stavimo neke numeričke i
# neke kategorijalne stupce iz našeg `data.framea` `podaci`.

summary(podaci[, c('mf_CareHarm', 'pi_age', 'pi_education')])

# Varijabla `pi_education`, koja sadrži razinu obrazovanja, je tipa `character`
# (odnosno, sadrži tekstualne vrijednosti). Kao što možemo vidjeti, output
# funkcije `summary()` nije koristan za varijable tog tipa. Budući da je
# `pi_education` kategorijalna varijabla, možemo je pretvoriti u tip `factor`,
# koji R koristi za označavanje takvih varijabli. To lako možemo učiniti
# koristeći funkciju `as.factor()`:

podaci$pi_education <- as.factor(podaci$pi_education)

# Ako ponovno pogledamo output funkcije `summary()`, vidjet ćemo da dobivamo
# korisnije podatke za ovakav tip varijable.

summary(podaci[, c('mf_CareHarm', 'pi_age', 'pi_education')])

##### select i filter

# Ranije smo vidjeli nekoliko načina na koje možemo odabirati varijable iz
# `data.framea` ili `tibblea`. Međutim, učitavanjem `tidyverse` paketa na
# raspolaganje nam je stavljena i funkcija `select()` koja nudi neke nove
# mogućnosti. Također, vidjeli smo kako možemo odabrati određene redove iz
# tablice s podacima. Sada ćemo vidjeti kako možemo iskoristiti funkciju
# `filter()` za filtriranje podataka u tablici.

# Na primjer, pogledajmo kako bismo mogli prikazati deskriptivnu
# statistiku za pitanja koja tvore jednu od skala koja se nalazi u našim
# podacima - skalu internalizacije moralnog identiteta - samo na poduzorku žena.

# Sve varijable koje se odnose na tu skalu imaju ime oblika
# `moralIdentityInternalization<broj-pitanja>`. Zbog tog sustavnog imenovanja,
# ne moramo ispisivati imena (ili redne brojeve) svih varijabli za koje želimo
# dobiti deskriptivnu statistiku, nego možemo pozvati funkciju `contains()` unutar
# funkcije `select()`.

# `contains()` nam omogućuje da odaberemo samo one varijable koje sadrže zadani
# string.

select(podaci,
       contains('internal',
                # ignore.case govori treba li
                # poštivati ili ignorirati
                # malo/veliko slovo
                ignore.case = T))

# Ova naredba nam vraća samo stupce koji u sebi sadrže "internal". Međutim,
# rekli smo i da želimo dobiti podatke koji se odnose samo na žene. Da bismo
# iz cijelog uzorka odabrali samo žene, koristit ćemo funkciju `filter()`:

filter(podaci, pi_gender == 'Female')

# Ove dvije naredbe možemo ulančati koristeći takozvani *pipe* operator `%>%`.
# On uzima output jedne funkcije i prosljeđuje ga u input druge funkcije. Dakle,
# funkcija `select()` nam vraća tablicu u kojoj se nalaze samo odabrani stupci.
# `filter()` nam vraća samo tablicu koja sadrži određene redove. Stoga,
# koristeći pipe operator, proslijedit ćemo tablicu koju dobivamo od funkcije
# `filter()` kao input u funkciju `select()`.

filter(podaci,
       pi_gender == 'Female') %>%
    select(.,
           contains('internal',
                    ignore.case = T))

# Output tog lanca dalje možemo proslijediti u `summary()`:

filter(podaci,
       pi_gender == 'Female') %>%
    select(.,
           contains('internal',
                    ignore.case = T)) %>%
    summary(.)

# Kad bismo htjeli koristiti samo osnovne R funkcije, cijeli ovaj proces bio bi
# nešto opsežniji za napisati i teži za čitati. Jedna od mogućnosti je:

summary(podaci[podaci$pi_gender == 'Female', c('moralIdentityInternalization01',
                                               'moralIdentityInternalization02',
                                               'moralIdentityInternalization03',
                                               'moralIdentityInternalization04',
                                               'moralIdentityInternalization05')])

# `contains` je jedna od nekoliko pomoćnih funkcija koje su super za `select`.
# Druge su:
# - `starts_with`, koja odabire varijable koje počinju s određenim stringom
# - `ends_with`, isto, samo za kraj
# - `matches`, koji nam omogućava da odaberemo varijable čija imena odgovaraju
# nekom *regularnom izrazu*

##### Regularni izrazi

# Regularni izrazi (eng. *regular expressions*, *regex* ili *regexp*) su
# stringovi koji označavaju neki uzorak za pretraživanje. Na primjer, sve ove
# izraze
# ```
# string
# striing
# striiing
# striiiiiiiiiiiiiiiiing
# ```
# možemo opisati regularnim izrazom `stri*ng`. Znak `*` (asterisk) je
# *kvantifikator* koji označava *nula ili više ponavljanja prethodnog znaka*.
# To znači da bi taj regularni izraz pronašao i string `strng`.

# Uz razne kvantifikatore, postoje još i klase znakova te meta-znakovi koji nam
# omogućavaju lako pretraživanje stringova.

# Regexi su implementirani u R-u (npr. funkcije `grep` i `grepl`) i u
# `tidyverse` skupini paketa kroz paket `stringr`. Mi ćemo se baviti
# `stringrom`. Budući da postoje razne implementacije regularnih izraza, koje se
# razlikuju po kompleksnosti, bitno je znati da `stringr` koristi *Perl/PCRE*
# regularne izraze.

# U ovom dijelu ćemo pogledati osnove regularnih izraza, koje ćemo nadograđivati
# kroz ostatak radionice.

##### Kvantifikatori

# Kao što je već rečeno, `*` označava *0 ili više* ponavljanja znaka, klase
# znakova ili grupe znakova koji mu prethodi. S klasama i grupama ćemo se
# upoznati malo kasnije.

# Pogledat ćemo output funkcije `str_detect()` koja kao input uzima string (ili
# više njih) i regularni izraz (`pattern`), a vraća `TRUE` ili `FALSE` ovisno o
# tome nalazi li se regularni izraz u stringu ili ne.

str_detect(string = c('kobilaaaa', 'maajka', 'celer'),
           pattern = 'a*')

# Regularni izraz `a*` traži, dakle, 0 ili više ponavljanja znaka `a`. Budući da
# sva tri zadana stringa sadrže nula ('celer') ili više ('kobilaaaa', 'maajka')
# ponavljanja znaka 'a', `str_detect()` vraća `TRUE` za sve zadane stringove.

# `+` označava *jedno (1) ili više* ponavljanja prethodnog znaka/klase
# znakova/grupe znakova.

# Da vidimo što će nam vratiti funkcija `str_extract_all()` koja prima iste
# argumente kao i `str_detect()`, a vraća sve pronađene `patterne`.

str_extract_all(string = c('kobilaaaa', 'maajka', 'celer'),
                pattern = 'a+')

# Postoji i funkcija `str_extract()` koja vraća *samo prvi* pronađeni uzorak.

str_extract(c('kobilaaaa', 'maajka', 'celer'),
            'a+')

# Također, možemo vidjeti da `str_detect()` više ne vraća `TRUE` za posljednju
# riječ.

str_detect(c('kobilaaaa', 'maajka', 'celer'),
           'a+')

# Ako želimo provjeriti javlja li se neki znak 0 ili 1 put, možemo koristiti
# `?`.

c('kobilaaaa', 'maajka', 'celer') %>%
    str_extract_all(.,
                    'a?')

# Ako želimo provjeriti javlja li se neki znak točno određen broj puta, možemo
# koristiti `{n,m}` sintaksu.

# Ova sintaksa nam omogućava da specificiramo koliko ponavljanja želimo. Postoje
# tri valjane kombinacije:
# - `{n,m}` znači od `n` do `m`
# - `{n,}` znači `n` ili više
# - `{n}` znači točno `n`
# `{,m}` *nije valjan* regularni izraz! Također, bitno je da nema razmaka između
# `n` ili `m` i zareza.

# Vratit ćemo se na početni primjer.

c('string', 'striing', 'striiing', 'striiiiiiiiiiiiiiiiing') %>%
    str_extract_all(.,
                    'i{2,5}')

c('string', 'striing', 'striiing', 'striiiiiiiiiiiiiiiiing') %>%
    str_extract_all(.,
                    'i{3,}')

c('string', 'striing', 'striiing', 'striiiiiiiiiiiiiiiiing') %>%
    str_extract_all(.,
                    'i{17}')

##### Klase znakova

# Pretraživanja koja smo dosad vidjeli su jednostavna i jako umjetna. U stvarnim
# primjenama uglavnom nećemo pokušavati uhvatiti jedno slovo, nego znakove
# određenog tipa (kao što su brojke) ili određene skupine znakova (npr. brojeve
# 1, 5 ili 7). U te svrhe, koristimo *klase znakova*.
#
# NB: Klase znakova predstavljaju više mogućih znakova, ali *samo jedno
# mjesto*.

# Napravit ćemo mali `data.frame` koji se sastoji od dva stupca koja sadrže
# stringove.

registracije <- data.frame('mjesta' = c('Slavonski Brod', 'BJELOVAR',
                                        'Cista Provo', 'Banova Jaruga'),
                           'tablice' = c('SB1152KF', 'BJ302LD',
                                         'CP999LO', 'BN2001KA'))

# Za početak, pokušat ćemo pronaći sva mjesta čija se imena sastoje od dvije
# riječi (to znači da ćemo isključiti BJELOVAR). Vidimo da sva mjesta koja
# se sastoje od dvije riječi imaju sljedeći uzorak: `[veliko slovo][nekoliko
# malih slova][razmak][veliko slovo][nekoliko malih slova]`. Koristeći regexe,
# možemo napraviti sljedeće:

registracije$mjesta %>%
    str_detect(.,
               '^[[:upper:]][[:lower:]]+\\s[[:upper:]][[:lower:]]+$')

# `^` (eng. *caret*) je meta-znak koji označava *početak stringa*.

# `[[:upper:]]` i `[[:lower:]]` su klase koje označavaju velika odnosno mala
# slova.

# `\\s` označava razmak (ostavljanje praznog mjesta također funkcionira). 

# Dakle, obrazac koji tražimo mora počinjati s velikim slovom kojem slijedi
# jedno ili više malih slova.

# Drugi važan meta-znak je `$`, koji označava *kraj stringa*.

# NB: Ako želimo tražiti same meta-znakove (npr. u `$1551`), ispred njih moramo
# staviti `\\` (backslash x 2). Taj čin se zove *escaping*.

c('$alaj', '€broj') %>%
    str_detect(.,
               '\\$')

# Koristeći uglate zagrade, možemo sami definirati klasu znakova koja je
# prihvatljiva na nekom mjestu. Na primjer, možemo tražiti sva mjesta koja imaju
# dvije riječi i čija prva riječ počinje slovom B (velikim!) ili S (također!).
# Ovdje ćemo koristiti `str_subset`, koja vraća stringove koji sadrže zadani
# obrazac.

registracije$mjesta %>%
    str_subset(.,
               '^[SB][[:lower:]]+\\s[[:upper:]][[:lower:]]+')

# Možemo definirati i vlastitu klasu znakova koji se *ne smiju* nalaziti na nekom
# mjestu. To radimo tako da na početak svoje klase stavimo znak `^` (`[^...]`).

# Na primjer, možemo tražiti stringove koji ne počinju slovom S ili B:

registracije$mjesta %>%
    str_subset(.,
               '^[^SB].*')

# Točka je poseban znak u regularnim izrazima, a označava *bilo koji znak* (osim
# novog reda, što se u R-u označava s `\\n`). Budući da označava bilo što, `.`
# se zove *wildcard*.

# Klasa znakova ima razmjerno puno, pa ćemo spomenuti još jednu koja se često
# javlja. Pokušat ćemo izvući samo one registracijske oznake (`tablice`) koje
# imaju tri znamenke.

registracije$tablice %>%
    str_subset(.,
               '[[:upper:]]{2}\\d{3}[[:upper:]]')

# `\\d`, dakle, označava znamenke.

# Zasad ćemo proći još samo kroz grupe znakova.

##### Grupe znakova

# Znakove možemo grupirati koristeći obične zagrade (`(...)`). Grupe spajaju
# znakove u jednu cjelinu. To nam, primjerice, omogućuje da ponavljajuće uzorke
# lako kvantificiramo. Na primjer, zamislimo da želimo izvući određene vrste
# smjehova iz nekih stringova.

c('hehehe', 'hehahohohehe', 'hahahahihi') %>%
    str_extract_all(.,
                    '(ha|he){2}')

# Ovdje smo iskoristili i znak `|` (kod mene se nalazi na `AltGr-W` i zove se
# *pipe*), koji označava alternaciju, odnosno logičko ILI. Dakle, tražimo dva
# ponavljanja stringa `ha ili he`.

# NB: Ne stavljati razmake oko alternatora jer će se to tumačiti kao razmak koji
# treba tražiti u stringu!

##### Nastavak pripreme podataka

# Zasad smo pogledali strukturu podatka (`str()` ili `glimpse()`), kako
# izgledaju sirovi podaci (`head` i `tail`) te neke statističke sažetke
# (`summary`). Sad ćemo se baciti na formatiranje sirovih podataka u nešto što
# nam je zgodnije za rad.

# Prvo ćemo se prisjetiti strukture podatka kojima baratamo.

glimpse(podaci)

# Za početak, iskoristit ćemo moći opažanja i primijetiti da su varijable koje
# počinju s `pi` (osim `pi_age` i `pi_education`) spremljene kao `character`
# vektori. Taj tip vrijednosti nije zgodan za većinu obrada koje bismo mogli
# htjeti raditi i razlog je zašto nam `summary()` vraća nekoristan sažetak.

##### Baratanje kategoričkim varijablama

# Stoga, pretvorit ćemo te varijable iz `charactera` u `factore`.

# Varijable možemo modificirati koristeći `mutate` obitelj funkcija. Ovdje ćemo
# iskoristiti `mutate_at()`, koji nam omogućuje da specificiramo varijable na
# koje želimo primijeniti neku funkciju. Uhvatit ćemo sve `pi` varijable osim
# `pi_age` i `pi_education` te na njih primijeniti funkciju `as.factor()`, koja
# će ih pretvoriti u `factore`.

# Budući da će `mutate_at()` zadanu funkciju primijeniti na postojeće stupce,
# dobro je (a) uvjeriti se da biramo prave stupce i (b) uvjeriti se da radimo
# ono što želimo raditi prije nego što spremimo promjene.

# (a) ćemo riješiti koristeći `colnames()` i `select()`.

podaci %>%
    select(.,
           starts_with('pi'),
           -c(pi_age, pi_education)) %>%
    colnames(.)

# Vidimo da ciljamo ispravne stupce. Sad možemo eksperimentirati s
# `mutate_at()`.

podaci %>%
    mutate_at(.,
              # varijable koje želimo zahvatiti treba omotati u
              # funkciju `vars()`; ona prima iste pomoćne funkcije kao
              # i `select()`
              .vars = vars(starts_with('pi'),
                           -c(pi_age, pi_education)),
              .fun = as.factor) %>%
    # ovaj dio je samo radi prikazivanja
    select(.,
           starts_with('pi')) %>%
    glimpse(.)

# Zadovoljni smo outputom, pa možemo spremiti promjene.

podaci <- podaci %>%
    mutate_at(.,
              .vars = vars(starts_with('pi'),
                           -c(pi_age, pi_education)),
              .fun = as.factor)

glimpse(podaci)

# Ako sad pozovemo `summary()`, dobit ćemo korisnije rezultate.

podaci %>%
    select(.,
           starts_with('pi_'),
           -c(pi_age)) %>%
    summary(.)

# Gledajući output ove funkcije, primjećujemo da su pojedine vrijednosti
# prilično dugačke (npr. 'Some professional diploma no degree').

# Koristeći `forcats` paket (dio `tidyversea`), vrlo lako možemo rekodirati te
# vrijednosti. To ćemo učiniti pomoću funkcije `fct_recode()`:

podaci$pi_education <- podaci$pi_education %>%
    fct_recode(.,
               'elem-sch' = "Elementary School",
               'hi-sch' = "High school",
               'masters' = "Master's degree",
               'phd' = "PhD or higher",
               'prof-dip' = "Some professional diploma no degree",
               'bac' = "The baccalaureate")

# Razine `factor` varijable možemo dohvatiti pomoću `levels()` funkcije:

levels(podaci$pi_education)

# Isto možemo napraviti s varijablom `pi_income`. Rekodirat ćemo razine tako da
# `avg` označava `About the average`, a razine ispod i iznad toga označit ćemo
# dodavanjem odgovarajućeg broja slova 'm' (kao 'minu') odnosno 'p' (kao 'plus')
# na kraj (npr. `avg_m` ili `avg_pp`).

podaci$pi_income <- podaci$pi_income %>%
    fct_recode(.,
               'avg' = "About the average",
               'avg_pp' = "Much above the average",
               'avg_mm' = "Much below the average", 
               'avg_p' = "Somewhat above the average",
               'avg_m' = "Somewhat below the average")

# Ovdje možemo primijetiti da je redoslijed razina podosta besmislen, tako da
# ćemo ih izvrtiti tako da idu od najniže do najviše. To ćemo učiniti pomoću
# funkcije `fct_relevel()`.

podaci$pi_income <- podaci$pi_income %>%
    fct_relevel(.,
                'avg_mm', 'avg_m', 'avg', 'avg_p', 'avg_pp')

podaci$pi_income

##### Preimenovanje varijabli

# Nekad su imena varijabli jako nezgrapna, neinformativna, mutava i slično. Budući da ćete se prije ili poslije susresti s takvim imenima, proći ćemo kroz nekoliko načina za mijenjanje imena varijabli.

# Ako želimo promijeniti imena manjeg broja varijabli, možemo koristiti funkciju `rename`. Na primjer, varijable `charitableBehavior01` i `charitableBehavior02` ne govore ništa o tome što su. Jedna je namjera doniranja novca, a druga namjera doniranja vremena. Stoga, preimenovat ćemo ih u `donationMoney` i `donationTime`.

podaci %>%
select(10:11) %>%
colnames(.)

podaci %<>%
rename(., donationMoney = charitableBehavior01,
      donationTime = charitableBehavior02)

podaci %>%
select(10:11) %>%
colnames(.)

# Ako trebamo preimenovati veći broj varijabli i ako smo te sreće da njihova imena možemo uhvatiti regularnim izrazima, možemo koristiti `str_replace`.

# Na primjer, imamo 32 varijable koje se zovu `moralFoundationsXX` i koje predstavljaju pitanja na Moral Foundations Questionnaireu. MFQ se sastoji od 5 faktora (authority, care, loyalty, fairness, sanctity) - svaki faktor reprezentiran je sa 6 pitanja. Osim toga, ima i dvije kontrolne čestice.

# Preimenovat ćemo varijable tako da na kraj imena svake od njih dodamo oznaku faktora kojoj pripada. Za to ćemo koristiti funkciju `str_replace`, koja nam omogućuje da neki obrazac definiran regexom zamijenimo nekim drugim stringom.

qc(orahovica, orašar) %>%
str_replace(., 'ora(h|š)', 'bor')

# Sad ćemo vidjeti kako ovu funkciju možemo koristiti za preimenovati varijable.

# dohvaćamo imena stupaca
colnames(podaci) %>%
# specificiramo stupce na kojima želimo izvršiti zamjenu
str_replace(., pattern = '(moralFoundations)(01|07|12|17|23|28)',
                     replacement = '\\1\\2_care') %>%
# ovo je samo radi prikazivanja svih MFQ pitanja
str_subset(., 'moralFoundations') %>% print(.)

# Vidimo da pitanja koja smo odredili sada imaju sufiks `_care`.

# U `replacement` argumentu smo iskoristili mogućnost referenciranja koju nam nudi grupiranje znakova u regularnim izrazima. Počevši s lijeva, svaku grupu definiranu pomoću `(...)` možemo dohvatiti pomoću `\\n`, gdje `n` označava redni broj grupe.

# Dakle, u gornjem primjeru se pri izvršavanju zamjene `\\1` širi u prvu pronađenu grupu (moralFoundations), a `\\2` u drugu pronađenu grupu (01, 07, 12, 17, 23 ili 28, ovisno o tome što je u pojedinom stringu pronađeno). Time dobivamo `moralFoundations01_care`, `moralFoundations07_care` itd.

# Kod ovakvog mijenjanja imena je zgodno to što nam se svaki put vraćaju imena svih stupaca - ako u imenu nekog stupca nije pronađen uzorak koji smo specificirali u `pattern`, ono ostaje netaknuto. Zbog toga, možemo napraviti lanac poziva `str_replace` pomoću pipa.

colnames(podaci) %>%
    str_replace(., '(moralFoundations)(01|07|12|17|23|28)', '\\1\\2_care') %>%
    str_replace(., '(moralFoundations)(02|08|13|18|24|29)', '\\1\\2_fair') %>%
    str_replace(., '(moralFoundations)(03|09|14|19|25|30)', '\\1\\2_loyal') %>%
    str_replace(., '(moralFoundations)(04|10|15|20|26|31)', '\\1\\2_author') %>%
    str_replace(., '(moralFoundations)(05|11|16|21|27|32)', '\\1\\2_sanct') %>%
    str_replace(., '(moralFoundations)(06|22)', '\\1\\2_control') %>%
print(.)

# Kad smo sigurni da dobivamo ono što očekujemo, samo promijenimo pipu `%>%` u `%<>%`.

colnames(podaci) %<>%
    str_replace(., '(moralFoundations)(01|07|12|17|23|28)', '\\1\\2_care') %>%
    str_replace(., '(moralFoundations)(02|08|13|18|24|29)', '\\1\\2_fair') %>%
    str_replace(., '(moralFoundations)(03|09|14|19|25|30)', '\\1\\2_loyal') %>%
    str_replace(., '(moralFoundations)(04|10|15|20|26|31)', '\\1\\2_author') %>%
    str_replace(., '(moralFoundations)(05|11|16|21|27|32)', '\\1\\2_sanct') %>%
    str_replace(., '(moralFoundations)(06|22)', '\\1\\2_control')

colnames(podaci) %>% print(.)

# Varijable u ovom setu zapravo su dosta dobro imenovane. Neke nisu dovoljno jasne, ali imenovanje je sustavno, što uvelike olakšava baratnje podacima.

# Nekad (kad radite s podacima sa Survey Monkeyja, recimo) vjerojatno nećete imati toliko jasne slučajeve. Na primjer, ime varijable moglo bi biti `1. Molimo Vas, odaberite vaš ekonomski status`. Takva imena su pakao. Kad bismo tako imenovanu varijablu ubacili u R, dobili bismo nešto ružno.

ruzno <- data.frame('1. Molimo Vas, odaberite vaš ekonomski status:' = 1:5)
print(ruzno)

# Svaki razmak postao je točka, zarez i dvotočka također su postali točke, a imenu varijable dodan je prefiks `X` (jer ime varijable ne može započinjati brojem!).

# Možemo pozvati funkciju `clean_names` iz paketa `janitor`, koja će od ružnih imena napraviti nešto ljepša.

lijepo <- clean_names(ruzno)
print(lijepo)

# Ovisno o konkretnom imenu, ova će funkcija biti manje ili više korisna. Recimo, ako je potrebno u potpunosti preimenovati varijablu u nešto smisleno, nema druge nego ručno.
#
# Ipak, isplati se pozvati `clean_names` jer može uvelike olakšati automatizirano preimenovanje.

# Dodat ćemo još 2 ružna stupca u `data.frame` `ruzno`.

ruzno %<>% data.frame(., '2. Koliko sam vina ja popio?' = 15:19,
                    '3. Je li vaše ludo srce biralo?' = F)
print(ruzno)

# Vidimo da su i upitnici pretvoreni u točke.

# Recimo da hoćemo svako ime svesti na format `[broj pitanja]_[prva riječ]`. Ako dopustimo R-u da obavi svoju masovnu konverziju, pa takva imena pretvaramo, mogli bismo imati problema (ili više nepotrebne patnje) sa specificiranjem obrasca koji želimo odbaciti.

# Ponovno ćemo pozvati `clean_names`:

lijepo <- clean_names(ruzno)
print(lijepo)

# Ova imena su puno sustavnija, zbog čega je lakše napisati neki obrazac znakova koji želimo zadržati. Za primjer, svest ćemo imena varijabli na format `[broj pitanja]_[prva riječ]`.

colnames(lijepo) %<>%
str_replace(., '^x(\\d_[[:lower:]]+).*', '\\1')
print(lijepo)

#
# ### Obrnuto kodiranje varijabli

# Neka od pitanja u ovom upitnik potrebno je obrnuto kodirati. To možemo učiniti pomoću funkcije `reverse.code` iz `psych` paketa. Ta funkcija ima dva obavezna argumenta: `keys`, koji je vektor brojki `1` i `-1`, te `items`, što su čestice koje treba rekodirati.

# Za primjer, rekodirat ćemo 3. i 4. pitanje skale `moralIdentityInternalization`.

podaci %>%
select(contains('Internal')) %>%
head(.) %T>% print(.) %>%
{reverse.code(keys = c(1, 1, -1, -1, 1),
                    items = .,
                    # zadajemo maksimum i minimum skale
                    # jer inače određuje prema vrijednostima
                    # koje se zapravo pojavljuju, a neke
                    # čestice imaju manji raspon od
                    # teoretski mogućeg
                    mini = 0, maxi = 7)} %T>%
str(.) %>% head(.)

# Sad kad smo se uvjerili da su varijable ispravno rekodirane, možemo skratiti postupak (recimo, tako da ciljamo samo one varijable koje zapravo treba rekodirati) i te rekodirane varijable dodati u `data.frame`.

podaci %<>%
# contains smo promijenili u matches
select(matches('Internal.*(03|04)$')) %>%
# u keys ostavljamo samo onoliko -1 koliko
# imamo varijabli
{reverse.code(keys = c(-1, -1),
                    items = .,
                    mini = 0, maxi = 7)} %>%
# reverse.code nam vraća matrix, pa ga pretvaramo
# u data.frame
as.data.frame(.) %$%
# otkrivamo imena varijabli kako bismo ih mogli
# koristiti direktno; tibble je dio tidyversea
add_column(podaci,
                   moralIdentityInternalization03_rec =
                   # ime varijable moramo staviti u `` (backticks)
                   # jer R inače baca error zbog - na kraju imena
                   # (taj - tumači kao sintaksu, a ne kao dio imena)
                   `moralIdentityInternalization03-`,
                   moralIdentityInternalization04_rec =
                   `moralIdentityInternalization04-`,
                   # pomoću .after definiramo iza kojeg stupca
                   # želimo dodati nove stupce; ovdje to radimo
                   # zato da bi mII varijable bile na okupu
                   .after = 'moralIdentityInternalization05')

colnames(podaci) %>% print(.)

#
# ### Brisanje stupaca

# Ponekad se u podacima nađu varijable koje nam nisu potrebne, pa je zgodno znati kako ih možemo obrisati. Za potrebe ove demonstracije, obrisat ćemo dvije varijable - `mf_CareHarm` i `mf_FairnessCheating` - koje su ukupni rezultati na dvije subskale MFQ-a.

# Jedan način za brisanje je upisivanje posebne vrijednosti `NULL` u stupac kojeg se želimo riješiti.

podaci$mf_CareHarm <- NULL

podaci %>% select(., starts_with('mf_')) %>% str(.)

# Drugi je prepisivanje (u smislu *overwrite*) varijable koja drži `data.frame` `data.frameom` koji sadrži sve varijable osim te koju želimo ukloniti. To možemo učiniti pomoću funkcije `select` i negacijskog operatora `-`.

podaci %<>%
select(-mf_FairnessCheating)

podaci %>% select(., starts_with('mf_')) %>% str(.)

#
# ### Stvaranje nove varijable pomoću `mutate`

# Već smo vidjeli neke načine na koje možemo stvarati nove varijable. Sada ćemo pomoću funkcije `mutate` rekreirati dva stupca koja smo malo prije obrisali.
#
# Kao rezultat na subskali uzet ćemo prosječnu vrijednost odabranih odgovora svakog sudionika.

podaci %>%
# koristimo rowMeans, koji računa aritmetičku sredinu svakog reda,
# kao što i samo ime kaže. funkciju primjenjujemo na varijable
# koje završavaju s 'care', što možemo napraviti jer smo bili
# mudri i smisleno i sustavno imenovali varijable
mutate(.,
             mf_CareHarm = rowMeans(select(.,
                                                  ends_with('care'))),
             mf_FairnessCheating = rowMeans(select(.,
                                                          ends_with('fair')))) %>%
# kad koristimo select, redoslijed kojim unosimo varijable u funkciju
# određuje redoslijed varijabli nakon odabira stupaca. stoga, budući da
# mutate vraća data.frame, možemo iskoristiti select da nove varijable
# preselimo do njima srodnih. primijetit ćemo da u selectu možemo
# kombinirati numeričke indekse i imena varijabli; koristimo
# everything() za dodavanje svih preostalih varijabli
select(., 1:mf_SanctityDegradation, mf_CareHarm, mf_FairnessCheating,
      everything()) %>% str(.)

# Vidimo da dobivamo što smo i htjeli, pa spremamo promjene.

podaci %<>%
mutate(.,
              mf_CareHarm = rowMeans(select(.,
                                                   ends_with('care'))),
              mf_FairnessCheating = rowMeans(select(.,
                                                    ends_with('fair')))) %>%
select(., 1:mf_SanctityDegradation, mf_CareHarm, mf_FairnessCheating,
              everything())

#
# ## Long i wide formati podataka

# Podaci kojima cijelo vrijeme baratamo nalaze se u *wide* formatu - svaki red predstavlja jedan *case* (u našem slučaju sudionika), a svaki stupac predstavlja jednu varijablu. Često, to je format s kojim želimo raditi.

# Ipak, ponekad nam je zgodno podatke prebaciti u *long* format, u kojem svaki *case* zauzima nekoliko redova. Takav format je potreban za, recimo, multilevel modeliranje u R-u.

# Za potrebe demonstracije prebacivanja iz jednog formata u drugi, napravit ćemo novi `data.frame`, koji sadrži podskup varijabli i *caseova* iz `data.framea` `podaci`.

podaci %>%
# slice nam omogućuje da biramo
# redove prema indeksu. uzet ćemo
# prvih 10 sudionika
slice(., 1:10) %>%
select(pi_gender, starts_with('descriptive')) %>%
# dodajemo eksplicitni indeks za svakog sudionika
add_column(., sub_index = 1:nrow(.)) ->
podaci_wide

podaci_wide

# `podaci_wide`, dakle, sadrži podskup `podataka`, u wide formatu. Sad ćemo taj `data.frame` prebaciti u long format, koristeći funkciju `gather` (kao, bacamo sve na hrpu) iz `tidyr` paketa.

# `gatheru` moramo dati neku tablicu s podacima (dakle, recimo, `data.frame`), odrediti ime varijable koja će služiti kao `key`, ime varijable koja će služiti kao `value`, te stupce koje želimo svesti na `key` - `value` format.

podaci_wide %>%
gather(., key = 'pitanje', value = 'odgovor',
             descriptiveSocialNorms01:descriptiveSocialNorms04) ->
podaci_long

podaci_long

# Za prebacivanje natrag u wide format, koristimo `spread` (kao, bacanje đubreta po livadi).

# Ovoj funkciji trebamo dati podatke (recimo, `data.frame`), `key` koji želimo "rastaviti" i `value`, što su vrijednosti koje trebamo potpisati pod stupce nastale rastavljanjem `key`.
#
# `spread` uzima jedinstvene vrijednosti iz varijable navedene kao `key` i širi ih u nove varijable, koje potom puni vrijednostima zadanima pod `value`.

podaci_long %>%
spread(., key = pitanje, value = odgovor) %>%
arrange(., sub_index)
