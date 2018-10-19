package nure.bpid.rsa.core;

/**
 * Created by Alexander on 02.04.2015.
 */
public class KeyPair {
    private final long key;
    private final long N;

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
