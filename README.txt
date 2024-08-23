/*IMPLEMENTATION of AES Algorythm by Björn Klein
The goal was to understand how AES works (I learned the working of AES Algorithm with the youtube videos from NESO Academy on AES https://www.youtube.com/watch?v=3MPkc-PFSRI&t=258s, where he explains the theorie about AES algorithm)
After understanding the theory of how it works, I  created my own AES Implementation without using anything else beside standard c libraries to be used on my Arduino/ESP32 Projects.
The project is a proof of concept and is not fine tuned / optimized now also structure is right now all in one file as it is easyer to use in ESP32. I will maybe create a library later
*/


to compile : gcc AES -o AES
to run ./AES

When you run the binary you can enter a Phrase that is then AES256 encrypted , the cypjhertext is printed out, it is decrypted and the decrypted text is printed out