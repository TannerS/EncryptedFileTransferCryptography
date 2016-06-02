

public final class Chunk extends Message {

    private static final long serialVersionUID = 0L;
    
    private final int seq;
    private final byte[] data;
    private final int crc;
    
    /**
     * 
     * @param seq The sequence number for the chunk.
     * @param data The encrypted data for the chunk.
     * @param crc The CRC32 value for the plaintext of the chunk's data.
     */
    public Chunk(int seq, byte[] data, int crc) {
        super(MessageType.CHUNK);
        this.seq = seq;
        this.data = data;
        this.crc = crc;
    }

    /**
     * 
     * @return The sequence number for the chunk.
     */
    public int getSeq() {
        return seq;
    }

    /**
     * 
     * @return The encrypted data for the chunk.
     */
    public byte[] getData() {
        return data;
    }

    /**
     * 
     * @return The CRC32 value for the plaintext of the chunk's data.
     */
    public int getCrc() {
        return crc;
    }
}
