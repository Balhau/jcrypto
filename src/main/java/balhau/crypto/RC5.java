package balhau.crypto;

import balhau.matematica.MathUtils;
import balhau.utils.ArrayUtils;

/**
 * Algoritmo RC5 inventado por Ronald Rivest em 1994 (RC-> Rivest Cypher) 
 * @author balhau
 *
 */
public class RC5 {
	/**
	 * Array de inteiros representando a chave privada do algoritmo quando numa arquitectura 64bits
	 */
	private int[] _key;
	/**
	 * Array de inteiros que representa a expansão da chave para uma arquitectura a 32 bits
	 */
	@SuppressWarnings("unused")
	private int[] _keyexp32;
	/**
	 * Array de inteiros que representa a expansão da chave para uma arquitectura a 16 bits
	 */
	@SuppressWarnings("unused")
	private short[] _keyexp16;
	/**
	 * Array de inteiros que representa a expansão da chave para uma arquitectura a 64 bits
	 */
	@SuppressWarnings("unused")
	private long[] _keyexp64;
	/**
	 * Comprimento, em bits, das palavras utilizadas no algoritmo
	 */
	private RC5WS _wzise;
	/**
	 * Número de rounds utilizados pelo algoritmo
	 */
	private int _nround;
	/**
	 * Número de bytes utilizado pela palavra chave
	 */
	private int _npkbytes;
	@SuppressWarnings("unused")
	private int[] _ktable32;
	@SuppressWarnings("unused")
	private short[] _ktable16;
	@SuppressWarnings("unused")
	private long[] _ktable64;
	private double _magP;
	private double _magQ;
	/**
	 * Construtor com especificação das propriedades do algoritmo
	 * @param wsize {@link int} comprimento da palavra
	 * @param nround {@link int} número de rounds utilizado pelo algoritmo
	 * @param nbytes {@link int} número de bytes presentes na palavra chave
	 */
	public RC5(RC5WS ws,int nround){
		this._nround=nround;
		this._npkbytes=255;
		this._wzise=ws;
		this._magP=this.Impar((Math.E-2)*Math.pow(2, this.wsToInt(ws)));
		this._magQ=this.Impar((MathUtils.NUMMAGICO-1)*Math.pow(2, this.wsToInt(ws)));
		genKey();
	}
	
	private void genKey(){
		ArrayUtils.getIntRandValues(this._npkbytes);
	}
	
	private void genExpKey(){
		switch (this._wzise) {
		case S16:
			break;
		case S32:
			break;
		case S64:
			break;
		default:
			break;
		}
	}
	
	private void genShortExpKey(){
		int u=wsToInt(_wzise)/8;
		int comp=(int)Math.ceil(((double)this._npkbytes)/u);
		this._keyexp16=new short[comp];
	}
	
	private void genIntExpKey(){
		int u=wsToInt(_wzise)/8;
		int comp=(int)Math.ceil(((double)this._npkbytes)/u);
		this._keyexp32=new int[comp];
		for(int i=0;i<comp;i++){
			
		}
	}
	
	private int wsToInt(RC5WS ws){
		switch (ws) {
			case S16: return 16;
			case S32: return 32;
			case S64: return 64;
			default: return 32;
		}
	}
	
	/**
	 * Método que devolve o número impar mais próximo de um valor
	 * @param a {@link double} valor A
	 * @return impar mais proximo de A
	 */
	private double Impar(double a){
		if((Math.floor(a)%2)==0)
			return Math.ceil(a);
		return Math.floor(a);
	}
	
	
}
