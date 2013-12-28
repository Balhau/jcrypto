package balhau.crypto;

import balhau.utils.ArrayUtils;

/**
 * Cifra de Vernam, também conhecida como cifra one-time-pad. Esta cifra encripta os dados criando uma
 * chave com o mesmo comprimento que os dados a encriptar, efectuando a operação XOR entre os sucessivos
 * bytes do texto. 
 * @author balhau
 *
 */
public class Vernam {
	/**
	 * Codificação a partir do algoritmo de Vernam
	 * @param data {@link int[]} com os valores dos dados a codificar 
	 * @return {@link VernamData} que contém informação sobre os dados codificados e a respectiva
	 * chave utilizada para a codificação
	 */
	public static CriptoData encode(int[] data){
		int[] key=ArrayUtils.getRandValues(data.length);
		return new CriptoData(ArrayUtils.IntXORInt(data, key), key);
	}
	
	/**
	 * Descodificação a partir do algoritmo de Vernam  
	 * @param cod {@link VernamData} com a informação necessária para descodificação dos dados
	 * @return {@link int[]} dados descodificados a partir do algoritmo de Vernam
	 */
	public static int[] decode(CriptoData cod){
		return ArrayUtils.IntXORInt(cod.Data, cod.Key);
	}
}
