package balhau.crypto;


import balhau.utils.Mask;
import balhau.utils.ArrayUtils;

/**
 * Algoritmo de encriptação {@link Camellia}. A sua espeficicação pode ser consultada em RFC3713
 * O algoritmo Camellia é muito parecido ao AES. Tem no entanto uma maior versatilidade
 * para implementações em hardware. Foi seleccionado pelo projecto NESSIE como um dos principais algoritmos
 * de encriptação. Está também na lista das técnicas de criptografia do Japonês e-government CRYPTREC.<br><br>
 * <b>Referências:<b><br>
 * <a href="http://tools.ietf.org/html/draft-nakajima-camellia-03">IETF Camellia Reference</a><br>
 * @author balhau
 */
public class Camellia {	
	/**
	 * Left key bytes
	 */
	private int[] KL;
	/**
	 * Right key bytes
	 */
	private int[] KR;
	
	private int[] K;
	
	private static int[] sbox1;
	/**
	 * Constante de Feistel sigma
	 */
	private static int[][] sigma={{0xA09E667F,0x3BCC908B},{0xB67AE858,0x4CAA73B2},{0xC6EF372F,0xE94F82BE},
	{0x54FF53A5,0xF1D36F1C},{0x10E527FA,0xDE682D1D},{0xB05688C2,0xB3E6C1FD}};
	
	/***
	 * Construtor da classe {@link Camellia}.
	 */
	public Camellia(){
		this.KL=new int[4];
		this.KR=new int[4];
	}
	/**
	 * Método que gera uma chave em função do tipo de encriptação {@link CamelliaType} 
	 * @param kt {@link CamelliaType} Enumerado representando o tipo de encriptação
	 */
	private void genKey(CamelliaType kt){
		switch (kt) {
		case Camellia128:
			this.K=new int[4];//4*32=128;
			this.K[0]=(int) Math.round(Math.random()*Integer.MAX_VALUE);
			this.K[1]=(int) Math.round(Math.random()*Integer.MAX_VALUE);
			this.K[2]=(int) Math.round(Math.random()*Integer.MAX_VALUE);
			this.K[3]=(int) Math.round(Math.random()*Integer.MAX_VALUE);
			break;
		case Camellia192:
			this.K=new int[6];//6*32=192;
			this.K[0]=(int) Math.round(Math.random()*Integer.MAX_VALUE);
			this.K[1]=(int) Math.round(Math.random()*Integer.MAX_VALUE);
			this.K[2]=(int) Math.round(Math.random()*Integer.MAX_VALUE);
			this.K[3]=(int) Math.round(Math.random()*Integer.MAX_VALUE);
			this.K[4]=(int) Math.round(Math.random()*Integer.MAX_VALUE);
			this.K[5]=(int) Math.round(Math.random()*Integer.MAX_VALUE);
			break;
		case Camellia256:
			this.K=new int[8];//8*32=256
			this.K[0]=(int) Math.round(Math.random()*Integer.MAX_VALUE);
			this.K[1]=(int) Math.round(Math.random()*Integer.MAX_VALUE);
			this.K[2]=(int) Math.round(Math.random()*Integer.MAX_VALUE);
			this.K[3]=(int) Math.round(Math.random()*Integer.MAX_VALUE);
			this.K[4]=(int) Math.round(Math.random()*Integer.MAX_VALUE);
			this.K[5]=(int) Math.round(Math.random()*Integer.MAX_VALUE);
			this.K[6]=(int) Math.round(Math.random()*Integer.MAX_VALUE);
			this.K[7]=(int) Math.round(Math.random()*Integer.MAX_VALUE);
			break;
		default://case 128
			this.K=new int[4];//4*32=128;
			this.K[0]=(int) Math.round(Math.random()*Integer.MAX_VALUE);
			this.K[1]=(int) Math.round(Math.random()*Integer.MAX_VALUE);
			this.K[2]=(int) Math.round(Math.random()*Integer.MAX_VALUE);
			this.K[3]=(int) Math.round(Math.random()*Integer.MAX_VALUE);
			break;
		}
	}
	/**
	 * Método que recebe uma valor de 64 bits sob a forma de inteiros 32 bits [inl,inr] e uma subchave de 64 bits 
	 * @param inl {@link int} Leftmost 32 bits dos 64 bits 
	 * @param inr {@link int} Rightmost 32 bits dos 64 bits  
	 * @param kl {@link int} Leftmost 32 bits dos 64 bits
	 * @param kr {@link int} Rightmost 32 bis dos 64 bits
	 */
	private int[] F(int inl,int inr,int kl,int kr){
		int[] out={0,0};
		int[] in={inl,inr};
		int[] k={kl,kr};
		int[] x=ArrayUtils.IntXORInt(in,k);
		//temp vars
		int t1=(x[0]>>24)&Mask.MASK8;
		int t2=(x[0]>>16)&Mask.MASK8;
		int t3=(x[0]>>8)&Mask.MASK8;
		int t4=x[0]&Mask.MASK8;
		int t5=(x[1]>>24)&Mask.MASK8;
		int t6=(x[1]>>16)&Mask.MASK8;
		int t7=(x[1]>>8)&Mask.MASK8;
		int t8=(x[1])&Mask.MASK8;
		return out;
	}
	
	private void setupKey(CamelliaType kt){
		switch(kt){
		case Camellia128:
			this.KL=this.K.clone();
			this.KR[0]=0;
			this.KR[1]=0;
			this.KR[2]=0;
			this.KR[3]=0;
			break;
		case Camellia192:
			this.KL[0]=this.K[0];
			this.KL[1]=this.K[1];
			this.KL[2]=this.K[2];
			this.KL[3]=this.K[3];
			this.KR[0]=this.K[4];
			this.KR[1]=this.K[5];
			this.KR[2]=0;
			this.KR[3]=0;
			break;
		case Camellia256:
			this.KL[0]=this.K[0];
			this.KL[1]=this.K[1];
			this.KL[2]=this.K[2];
			this.KL[3]=this.K[3];
			this.KR[0]=this.K[4];
			this.KR[1]=this.K[5];
			this.KR[2]=this.K[6];
			this.KR[3]=this.K[7];
			break;
		default://caso default encriptação 128
			this.KL=this.K.clone();
			this.KR[0]=0;
			this.KR[1]=0;
			this.KR[2]=0;
			this.KR[3]=0;
		}
	}
}
