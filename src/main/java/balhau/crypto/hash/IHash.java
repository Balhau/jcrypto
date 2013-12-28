package balhau.crypto.hash;
/**
 * Interface para as várias funções de Hash
 * @author balhau
 *
 */
public interface IHash {
	/**
	 * Método para computar o hash de uma string
	 * @param msg {@link String}
	 * @return {@link String} Hash respectivo
	 */
	public String encode(String msg);
	/**
	 * Método para computar o hash de um bloco de caracteres
	 * @param msg {@link char[]} Array de caracteres
	 * @return {@link String} hash respectivo
	 */
	public String encode(byte[] msg);
	/**
	 * Método que finaliza o processamento da hash
	 */
	public void finish();
	/**
	 * Método que actualiza o valor da hash para um bloco de caracteres
	 * @param block {@link byte[]}
	 */
	public void update(byte[] block);
	/**
	 * Método que nos devolve uma string em Hexadecimal representando o valor da hash
	 * @return {@link String} Valor da hash
	 */
	public String hexDigest();
	/**
	 * Devolve o valor da hash sob a forma de array de caracteres
	 * @return {@link byte[]}
	 */
	public byte[] digest();
}
