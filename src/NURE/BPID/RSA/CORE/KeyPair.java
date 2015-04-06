package NURE.BPID.RSA.CORE;

/**
 * Created by Alexander on 02.04.2015.
 */
public class KeyPair {
    private long key;
    private long N;

    public KeyPair(long key, long N) {
        this.key = key;
        this.N = N;
    }

    public long getKey() {
        return key;
    }

    public long getN() {
        return N;
    }
}
