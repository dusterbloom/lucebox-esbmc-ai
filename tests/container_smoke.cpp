#include <cassert>
#include <vector>

int main() {
    std::vector<int> values = {1, 2, 3};
    assert(values.size() == 3);
    assert(values[0] == 1);
    return 0;
}
