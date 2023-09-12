#include <iostream>


struct Test{
    int a;
    int b;
}; 

void f(Test &t){
    if(t.b == 0x66666666 && t.a == 0x11223344){
        printf("yes");
    }else{
        printf("no");
    }
}

int main(){

    // 用angr猜出这个结构体的成员值
    Test t{};

    f(t);
    return 0;
}

