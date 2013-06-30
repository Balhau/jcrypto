/**
 * O pacote balhau.crypto.utils é o local para implementação de funcionalidades auxiliares ao desenvolvimento de ferramentas criptográficas
 */
package balhau.crypto.utils;
/**
 * Classe utilitaria que contém constantes e rotinas utilizadas nos variados algoritmos de encriptação
 * e hash
 * @author balhau
 *
 */
public class Crypto {
	
	private static String hex_str="0123456789ABCDEF";
	
	/**
	 * Método que transforma um valor inteiro para a sua representação hexadecimal
	 * @param val {@link int} Valor inteiro val
	 * @return {@link String} Representação hexadecimal do valor inteiro val  
	 */
	public static String IntToHex(int val){
		int aux=val;
		int dig=0;
		String out="";
		if(val==0)
			return "0";
		while(aux!=0){
			dig=aux&0xF;
			out=hex_str.charAt(dig)+out;
			aux=aux>>>4;
		}
		return out;
	}
}
