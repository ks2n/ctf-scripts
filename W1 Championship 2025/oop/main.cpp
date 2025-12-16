#include<bits/stdc++.h>

using namespace std;

using i64 = long long;
using u32 = unsigned;
using u64 = unsigned long long;

#define fi first
#define se second

template<class A, class B> inline bool maximize(A& x, B y) {
    if (x < y) {
        x = y;
        return true;
    } else
        return false;
};

template<class A, class B> inline bool minimize(A& x, B y) {
    if (x > y) {
        x = y;
        return true;
    } else
        return false;
};

void komasan() {
    char s[10];
    cin >> s;   
    cout << s;
}

int main() {
    ios_base::sync_with_stdio(false); 
    cin.tie(nullptr);
    
    // freopen(".inp", "r", stdin);
    // freopen(".out", "w", stdout);
    
    komasan();
}