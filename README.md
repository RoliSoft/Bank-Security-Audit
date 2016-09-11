# TLS/SSL Audit of Romanian Banks

Based on the "[Do you really want Bank Grade security?](http://www.troyhunt.com/2015/05/do-you-really-want-bank-grade-security.html)" post, I've decided to test the two banks I'm actively using, and see just how secure their TLS configuration is. After being rather disappointed with the results – even though I went in with lowered expectations – I've decided to embark on a journey to test all the banks and see if any of them score better. Since manually doing this was time-consuming and rather boring, I wrote a Python script to run the tests via the [Qualys SSL Labs API](https://www.ssllabs.com/projects/ssllabs-apis/) and fetch/export the results into a format I can easily paste into the spreadsheet.

It should be noted that this project only tests accepted protocols, chipers, other properties and known vulnerabilities in the TLS server. It does *NOT* take it any further and evaluate the security of the web application – such as CSRF/XSS/SQLi and other similar-sounding fancy acronyms – as those could be interpreted as actual attacks and would be highly illegal. The information being evaluated in this project all come from the TLS handshake made with the server, nothing nasty involved.

## Usage

To use the script, open `scan.py` and edit the global variables in order to configure it. Out-of-the-box it comes with a list loosely based on Wikipedia's [Romanian banks ordered by their assets](https://ro.wikipedia.org/wiki/Lista_b%C4%83ncilor_din_Rom%C3%A2nia) article.

After configuration, you can start the scan by running `scan.py start`. By default, the public API allows you to run 25 assessments simultaneously, so make sure to keep the list of hostnames under 25.

You can check in on the progress by running `scan.py info`, which will print the number of assessments still running that have been started by the script. When you see `0/25` it means all the assessments have finished, and you can either start the next batch of 25 or collect the results.

To collect the results, run `scan.py collect [file]` which will fetch the assessment results and print it in a tabulated fashion, which you can paste into Google Sheets.

In Google Sheets, you can set up rules for Conditional Formatting in order to automatically color the "Pass"/"Fail" cells and the grades.

## Test Results

The spreadsheet with the results of the Romanian banks can be accessed here: https://docs.google.com/spreadsheets/d/1z4_WoPR-53qUgClKwo8EMEotH7xcjfngtebG7nVJpec/edit?usp=sharing

I will try to update the spreadsheet above monthly, unless there was no change from last month's results. It should be interesting to see how their security evolves over time, and especially, how fast do banks react to patching 0-day TLS vulnerabilities, if they do at all.

The banks being tested by [Qualys SSL Labs](https://www.ssllabs.com/ssltest/) and [Mozilla Observatory](https://observatory.mozilla.org/) are:

* [Banca Transilvania (BT)](https://ro.wikipedia.org/wiki/Banca_Transilvania)
* [ING Bank](https://ro.wikipedia.org/wiki/ING_Bank_Rom%C3%A2nia)
* [Banca Română pentru Dezvoltare (BRD)](https://ro.wikipedia.org/wiki/BRD_-_Groupe_Soci%C3%A9t%C3%A9_G%C3%A9n%C3%A9rale)
* [Banca Comercială Română (BCR)](https://ro.wikipedia.org/wiki/Banca_Comercial%C4%83_Rom%C3%A2n%C4%83)
* [Raiffeisen Bank](https://ro.wikipedia.org/wiki/Raiffeisen_Bank_Rom%C3%A2nia)
* [CEC Bank](https://ro.wikipedia.org/wiki/CEC_Bank)
* [OTP Bank](https://ro.wikipedia.org/wiki/OTP_Bank_Rom%C3%A2nia)
* [UniCredit Bank](https://ro.wikipedia.org/wiki/UniCredit_Bank_Rom%C3%A2nia)
* [Alpha Bank](https://ro.wikipedia.org/wiki/Alpha_Bank_Rom%C3%A2nia)
* [Bancpost](https://ro.wikipedia.org/wiki/Bancpost)
* [Piraeus Bank](https://ro.wikipedia.org/wiki/Piraeus_Bank_Rom%C3%A2nia)
* [Credit Europe](https://ro.wikipedia.org/wiki/Credit_Europe_Bank_Rom%C3%A2nia)
* [Banca Românească](https://ro.wikipedia.org/wiki/Banca_Rom%C3%A2neasc%C4%83)
* [GarantiBank](https://ro.wikipedia.org/wiki/Garanti_Bank_Rom%C3%A2nia)
* [Intesa Sanpaolo Bank](https://ro.wikipedia.org/wiki/Intesa_Sanpaolo_Bank_Rom%C3%A2nia)
* [Banca Comercială Carpatica](https://ro.wikipedia.org/wiki/Banca_Comercial%C4%83_Carpatica)
* [Marfin Bank](https://ro.wikipedia.org/wiki/Marfin_Bank_Rom%C3%A2nia)
* [Millenium Bank](https://ro.wikipedia.org/wiki/Millennium_Bank_Rom%C3%A2nia)
* [Libra Internet Bank](https://ro.wikipedia.org/wiki/Libra_Bank)
* [Banca Comercială Feroviară (BCF)](https://ro.wikipedia.org/wiki/Banca_Comercial%C4%83_Feroviar%C4%83)

Some interesting notes:

* The good:

    * I made the first *manual* tests on May 16th and repeated them on June 18th. **BT**, **ING** and **Raiffeisen** went from their B/B/C grades respectively to **A**-, which was a pleasant surprise.

* The bad:

    * Some banks really don't like changing their SSL setup, even if a major vulnerabilty knocks on their door, as two of them are still vulnerable to the [POODLE attack](https://en.wikipedia.org/wiki/POODLE) as of June 29th, granting them the **F** grade.

    * Some banks really fucked up. As of June 29th, three banks all have their login forms on HTTP, and some of them even POST to HTTP and *only then* redirect to HTTPS. Their grades are forced to **F**, regardless of their actual TLS setup, until they fix it.
