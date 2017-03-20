//
// Created by Sasinda Premarathna on 3/20/17.
//
#include "gbn.h"
int main(){
    gbnhdr segi = {SYN, 0, 0, HEADLEN+2};
    segi.data[0]='a';
    segi.data[1]='b';

    segi.checksum = checksum(&segi, segi.length);
    printf("%d", segi.checksum);
}