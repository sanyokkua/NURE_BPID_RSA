package NURE.BPID.RSA.CORE;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

/**
 * Created by Alexander on 02.04.2015.
 */
public class RSA {
    private final int MAX_KEY_VALUE = 5000;
    private KeyPair publicPair;
    private KeyPair privatePair;
    private int maximumBitInKey;
    private byte[] originalTextInBytes;
    private long[] cipherText;
    private Random random;
    private Integer[] primesTo256;


    public RSA(int maximumBitInKey) {
        if (maximumBitInKey < 4 || maximumBitInKey > 9)
            throw new IllegalArgumentException("Number of bits must be bigger than 4 and smaller than 10");
        this.maximumBitInKey = maximumBitInKey;
        random = new Random();
        generatePrimesTo256();
    }

    private void generatePrimesTo256() {
        int size = 256;
        boolean[] temp = new boolean[size];
        Arrays.fill(temp, true);
        ArrayList<Integer> primes = new ArrayList<>();
        for (int p = 2; p < temp.length; p++) {
            if (temp[p]) {
                for (int j = p * 2; j < size; j += p) {
                    temp[j] = false;
                }
                primes.add(p);
            }
        }
        primesTo256 = primes.toArray(new Integer[primes.size()]);
    }

    public void encrypt(String text) {
        generatingKeys();
        originalTextInBytes = text.getBytes();
        doEncryption();
    }

    private void generatingKeys() {
        int p, q;
        p = generatePrimeNumber();
        do {
            q = generatePrimeNumber();
        } while (p == q);
        long n = p * q;
        long phi = (p - 1) * (q - 1);
        int e = getE(phi);
        int d = getD(phi, e);
        publicPair = new KeyPair(e, n);
        privatePair = new KeyPair(d, n);
    }

    private int generatePrimeNumber() {
        ArrayList<Integer> binary = new ArrayList<>();
        binary.add(1);
        for (int i = 1; i < maximumBitInKey; i++) {
            binary.add(Math.abs(random.nextInt() % 2));
        }
        int result = toDecimal(binary);
        while (!isPrime(result)) {
            result++;
        }
        return result;
    }

    private int toDecimal(ArrayList<Integer> binary) {
        int res = 0;
        for (int i = 0, j = binary.size() - 1; i < binary.size(); i++)
            res += binary.get(j--) * (1 << i);
        return res;
    }

    private boolean isPrime(int res) {
        for (int i : primesTo256) {
            if (res != i && res % i == 0)
                return false;
        }
        int sqrt = (int) Math.sqrt(res);
        for (int i = primesTo256[primesTo256.length - 1]; i < sqrt; i++) {
            if (res % i == 0)
                return false;
        }
        return true;
    }

    private int getE(long phi) {
        int e = Math.abs(random.nextInt(MAX_KEY_VALUE));
        for (; gcd(e, phi) != 1; e++) ;
        return e;
    }

    private long gcd(long a, long b) {
        while (a > 0 && b > 0)
            if (a > b) a %= b;
            else b %= a;
        return a + b;
    }

    private int getD(long phi, int e) {
        int d = Math.abs(random.nextInt(MAX_KEY_VALUE));
        for (; (d * e) % phi != 1; d++) ;
        return d;
    }

    private void doEncryption() {
        cipherText = new long[originalTextInBytes.length];
        int i = 0;
        for (byte symbol : originalTextInBytes) {
            cipherText[i++] = powerMod(symbol, publicPair.getKey(), publicPair.getN());
        }
    }

    private long powerMod(long value, long power, long mod) {
        value %= mod;
        long res = 1;
        while (power != 0) {
            if ((power & 1) != 0)
                res = (res * value) % mod;
            value = (value * value) % mod;
            power >>= 1;
        }
        return res;
    }

    public long[] getCipherText() {
        if (cipherText == null)
            throw new NullPointerException("Cipher text is not exist");
        return cipherText;
    }

    public KeyPair getPublicPair() {
        if (publicPair == null)
            throw new NullPointerException("Pair is not initialized");
        return publicPair;
    }

    public KeyPair getPrivatePair() {
        if (privatePair == null)
            throw new NullPointerException("Pair is not initialized");
        return privatePair;
    }

    public String decrypt(long[] cipherText, KeyPair privatePair) {
        byte[] decrypted = new byte[cipherText.length];
        int i = 0;
        for (long symbol : cipherText) {
            decrypted[i++] = (byte) powerMod(symbol, privatePair.getKey(), privatePair.getN());
        }
        StringBuilder builder = new StringBuilder();
        for (byte b : decrypted) {
            builder.append((char) b);
        }
        return builder.toString();
    }
}
