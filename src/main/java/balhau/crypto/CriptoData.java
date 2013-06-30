package balhau.crypto;

/**
 * Classe que representa o resultado da encriptação sob a forma de dados, chave 
 * @author balhau
 *
 */
public class CriptoData {
	/**
	 * Dados encriptados
	 */
	public int[] Data;
	/**
	 * Key utilizada para encriptar os dados
	 */
	public int[] Key;
	/**
	 * Construtor do objecto com especificação das propriedades Data e Key
	 * @param data dados {@link int[]} encriptados
	 * @param key {@link int[]} chave responsável pela encriptação dos dados
	 */
	public CriptoData(int[] data,int[] key){
		Data=data;
		Key=key;
	}
}
