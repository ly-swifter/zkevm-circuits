use eth_types::Field;
use halo2_proofs::{
    circuit::AssignedCell,
    halo2curves::{bn256::Fr, FieldExt},
};
use itertools::Itertools;
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::{
    gates::{flex_gate::FlexGateConfig, GateInstructions},
    AssignedValue, Context, QuantumCell,
};

use crate::{
    constants::{DIGEST_LEN, MAX_AGG_SNARKS, ROUND_LEN},
    DEFAULT_KECCAK_ROWS, NUM_ROUNDS,
};

use std::env::var;

pub(crate) fn capacity(num_rows: usize) -> Option<usize> {
    if num_rows > 0 {
        // Subtract two for unusable rows
        Some(num_rows / ((NUM_ROUNDS + 1) * get_num_rows_per_round()) - 2)
    } else {
        None
    }
}

pub(crate) fn get_num_rows_per_round() -> usize {
    var("KECCAK_ROWS")
        .unwrap_or_else(|_| format!("{DEFAULT_KECCAK_ROWS}"))
        .parse()
        .expect("Cannot parse KECCAK_ROWS env var as usize")
}

pub(crate) fn rlc(inputs: &[Fr], randomness: &Fr) -> Fr {
    assert!(inputs.len() > 0);
    let mut acc = inputs[0];
    for input in inputs.iter().skip(1) {
        acc = acc * *randomness + *input;
    }

    acc
}

/// Return
/// - the indices of the rows that contain the input preimages
/// - the indices of the rows that contain the output digest
pub(crate) fn get_indices(preimages: &[Vec<u8>]) -> (Vec<usize>, Vec<usize>) {
    // precomputed data for MAX_AGG_SNARKS == 10
    if MAX_AGG_SNARKS == 10 && preimages.len() == 10 {
        log::info!("use pre-computed indices");
        let preimage_indices = vec![
            12, 13, 14, 15, 16, 17, 18, 19, 24, 25, 26, 27, 28, 29, 30, 31, 36, 37, 38, 39, 40, 41,
            42, 43, 48, 49, 50, 51, 52, 53, 54, 55, 60, 61, 62, 63, 64, 65, 66, 67, 72, 73, 74, 75,
            76, 77, 78, 79, 84, 85, 86, 87, 88, 89, 90, 91, 96, 97, 98, 99, 100, 101, 102, 103,
            108, 109, 110, 111, 112, 113, 114, 115, 120, 121, 122, 123, 124, 125, 126, 127, 132,
            133, 134, 135, 136, 137, 138, 139, 144, 145, 146, 147, 148, 149, 150, 151, 156, 157,
            158, 159, 160, 161, 162, 163, 168, 169, 170, 171, 172, 173, 174, 175, 180, 181, 182,
            183, 184, 185, 186, 187, 192, 193, 194, 195, 196, 197, 198, 199, 204, 205, 206, 207,
            208, 209, 210, 211, 312, 313, 314, 315, 316, 317, 318, 319, 324, 325, 326, 327, 328,
            329, 330, 331, 336, 337, 338, 339, 340, 341, 342, 343, 348, 349, 350, 351, 352, 353,
            354, 355, 360, 361, 362, 363, 364, 365, 366, 367, 372, 373, 374, 375, 376, 377, 378,
            379, 384, 385, 386, 387, 388, 389, 390, 391, 396, 397, 398, 399, 400, 401, 402, 403,
            408, 409, 410, 411, 412, 413, 414, 415, 420, 421, 422, 423, 424, 425, 426, 427, 432,
            433, 434, 435, 436, 437, 438, 439, 444, 445, 446, 447, 448, 449, 450, 451, 456, 457,
            458, 459, 460, 461, 462, 463, 468, 469, 470, 471, 472, 473, 474, 475, 480, 481, 482,
            483, 484, 485, 486, 487, 492, 493, 494, 495, 496, 497, 498, 499, 504, 505, 506, 507,
            508, 509, 510, 511, 612, 613, 614, 615, 616, 617, 618, 619, 624, 625, 626, 627, 628,
            629, 630, 631, 636, 637, 638, 639, 640, 641, 642, 643, 648, 649, 650, 651, 652, 653,
            654, 655, 660, 661, 662, 663, 664, 665, 666, 667, 672, 673, 674, 675, 676, 677, 678,
            679, 684, 685, 686, 687, 688, 689, 690, 691, 696, 697, 698, 699, 700, 701, 702, 703,
            708, 709, 710, 711, 712, 713, 714, 715, 720, 721, 722, 723, 724, 725, 726, 727, 732,
            733, 734, 735, 736, 737, 738, 739, 744, 745, 746, 747, 748, 749, 750, 751, 756, 757,
            758, 759, 760, 761, 762, 763, 768, 769, 770, 771, 772, 773, 774, 775, 780, 781, 782,
            783, 784, 785, 786, 787, 792, 793, 794, 795, 796, 797, 798, 799, 804, 805, 806, 807,
            808, 809, 810, 811, 912, 913, 914, 915, 916, 917, 918, 919, 924, 925, 926, 927, 928,
            929, 930, 931, 936, 937, 938, 939, 940, 941, 942, 943, 948, 949, 950, 951, 952, 953,
            954, 955, 960, 961, 962, 963, 964, 965, 966, 967, 972, 973, 974, 975, 976, 977, 978,
            979, 984, 985, 986, 987, 988, 989, 990, 991, 996, 997, 998, 999, 1000, 1001, 1002,
            1003, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015, 1020, 1021, 1022, 1023, 1024,
            1025, 1026, 1027, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1044, 1045, 1046,
            1047, 1048, 1049, 1050, 1051, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1068,
            1069, 1070, 1071, 1072, 1073, 1074, 1075, 1080, 1081, 1082, 1083, 1084, 1085, 1086,
            1087, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1104, 1105, 1106, 1107, 1108,
            1109, 1110, 1111, 1212, 1213, 1214, 1215, 1216, 1217, 1218, 1219, 1224, 1225, 1226,
            1227, 1228, 1229, 1230, 1231, 1236, 1237, 1238, 1239, 1240, 1241, 1242, 1243, 1248,
            1249, 1250, 1251, 1252, 1253, 1254, 1255, 1260, 1261, 1262, 1263, 1264, 1265, 1266,
            1267, 1272, 1273, 1274, 1275, 1276, 1277, 1278, 1279, 1284, 1285, 1286, 1287, 1288,
            1289, 1290, 1291, 1296, 1297, 1298, 1299, 1300, 1301, 1302, 1303, 1308, 1309, 1310,
            1311, 1312, 1313, 1314, 1315, 1320, 1321, 1322, 1323, 1324, 1325, 1326, 1327, 1332,
            1333, 1334, 1335, 1336, 1337, 1338, 1339, 1344, 1345, 1346, 1347, 1348, 1349, 1350,
            1351, 1356, 1357, 1358, 1359, 1360, 1361, 1362, 1363, 1368, 1369, 1370, 1371, 1372,
            1373, 1374, 1375, 1380, 1381, 1382, 1383, 1384, 1385, 1386, 1387, 1392, 1393, 1394,
            1395, 1396, 1397, 1398, 1399, 1404, 1405, 1406, 1407, 1408, 1409, 1410, 1411, 1512,
            1513, 1514, 1515, 1516, 1517, 1518, 1519, 1524, 1525, 1526, 1527, 1528, 1529, 1530,
            1531, 1536, 1537, 1538, 1539, 1540, 1541, 1542, 1543, 1548, 1549, 1550, 1551, 1552,
            1553, 1554, 1555, 1560, 1561, 1562, 1563, 1564, 1565, 1566, 1567, 1572, 1573, 1574,
            1575, 1576, 1577, 1578, 1579, 1584, 1585, 1586, 1587, 1588, 1589, 1590, 1591, 1596,
            1597, 1598, 1599, 1600, 1601, 1602, 1603, 1608, 1609, 1610, 1611, 1612, 1613, 1614,
            1615, 1620, 1621, 1622, 1623, 1624, 1625, 1626, 1627, 1632, 1633, 1634, 1635, 1636,
            1637, 1638, 1639, 1644, 1645, 1646, 1647, 1648, 1649, 1650, 1651, 1656, 1657, 1658,
            1659, 1660, 1661, 1662, 1663, 1668, 1669, 1670, 1671, 1672, 1673, 1674, 1675, 1680,
            1681, 1682, 1683, 1684, 1685, 1686, 1687, 1692, 1693, 1694, 1695, 1696, 1697, 1698,
            1699, 1704, 1705, 1706, 1707, 1708, 1709, 1710, 1711, 1812, 1813, 1814, 1815, 1816,
            1817, 1818, 1819, 1824, 1825, 1826, 1827, 1828, 1829, 1830, 1831, 1836, 1837, 1838,
            1839, 1840, 1841, 1842, 1843, 1848, 1849, 1850, 1851, 1852, 1853, 1854, 1855, 1860,
            1861, 1862, 1863, 1864, 1865, 1866, 1867, 1872, 1873, 1874, 1875, 1876, 1877, 1878,
            1879, 1884, 1885, 1886, 1887, 1888, 1889, 1890, 1891, 1896, 1897, 1898, 1899, 1900,
            1901, 1902, 1903, 1908, 1909, 1910, 1911, 1912, 1913, 1914, 1915, 1920, 1921, 1922,
            1923, 1924, 1925, 1926, 1927, 1932, 1933, 1934, 1935, 1936, 1937, 1938, 1939, 1944,
            1945, 1946, 1947, 1948, 1949, 1950, 1951, 1956, 1957, 1958, 1959, 1960, 1961, 1962,
            1963, 1968, 1969, 1970, 1971, 1972, 1973, 1974, 1975, 1980, 1981, 1982, 1983, 1984,
            1985, 1986, 1987, 1992, 1993, 1994, 1995, 1996, 1997, 1998, 1999, 2004, 2005, 2006,
            2007, 2008, 2009, 2010, 2011, 2112, 2113, 2114, 2115, 2116, 2117, 2118, 2119, 2124,
            2125, 2126, 2127, 2128, 2129, 2130, 2131, 2136, 2137, 2138, 2139, 2140, 2141, 2142,
            2143, 2148, 2149, 2150, 2151, 2152, 2153, 2154, 2155, 2160, 2161, 2162, 2163, 2164,
            2165, 2166, 2167, 2172, 2173, 2174, 2175, 2176, 2177, 2178, 2179, 2184, 2185, 2186,
            2187, 2188, 2189, 2190, 2191, 2196, 2197, 2198, 2199, 2200, 2201, 2202, 2203, 2208,
            2209, 2210, 2211, 2212, 2213, 2214, 2215, 2220, 2221, 2222, 2223, 2224, 2225, 2226,
            2227, 2232, 2233, 2234, 2235, 2236, 2237, 2238, 2239, 2244, 2245, 2246, 2247, 2248,
            2249, 2250, 2251, 2256, 2257, 2258, 2259, 2260, 2261, 2262, 2263, 2268, 2269, 2270,
            2271, 2272, 2273, 2274, 2275, 2280, 2281, 2282, 2283, 2284, 2285, 2286, 2287, 2292,
            2293, 2294, 2295, 2296, 2297, 2298, 2299, 2304, 2305, 2306, 2307, 2308, 2309, 2310,
            2311, 2412, 2413, 2414, 2415, 2416, 2417, 2418, 2419, 2424, 2425, 2426, 2427, 2428,
            2429, 2430, 2431, 2436, 2437, 2438, 2439, 2440, 2441, 2442, 2443, 2448, 2449, 2450,
            2451, 2452, 2453, 2454, 2455, 2460, 2461, 2462, 2463, 2464, 2465, 2466, 2467, 2472,
            2473, 2474, 2475, 2476, 2477, 2478, 2479, 2484, 2485, 2486, 2487, 2488, 2489, 2490,
            2491, 2496, 2497, 2498, 2499, 2500, 2501, 2502, 2503, 2508, 2509, 2510, 2511, 2512,
            2513, 2514, 2515, 2520, 2521, 2522, 2523, 2524, 2525, 2526, 2527, 2532, 2533, 2534,
            2535, 2536, 2537, 2538, 2539, 2544, 2545, 2546, 2547, 2548, 2549, 2550, 2551, 2556,
            2557, 2558, 2559, 2560, 2561, 2562, 2563, 2568, 2569, 2570, 2571, 2572, 2573, 2574,
            2575, 2580, 2581, 2582, 2583, 2584, 2585, 2586, 2587, 2592, 2593, 2594, 2595, 2596,
            2597, 2598, 2599, 2604, 2605, 2606, 2607, 2608, 2609, 2610, 2611, 2712, 2713, 2714,
            2715, 2716, 2717, 2718, 2719, 2724, 2725, 2726, 2727, 2728, 2729, 2730, 2731, 2736,
            2737, 2738, 2739, 2740, 2741, 2742, 2743, 2748, 2749, 2750, 2751, 2752, 2753, 2754,
            2755, 2760, 2761, 2762, 2763, 2764, 2765, 2766, 2767, 2772, 2773, 2774, 2775, 2776,
            2777, 2778, 2779, 2784, 2785, 2786, 2787, 2788, 2789, 2790, 2791, 2796, 2797, 2798,
            2799, 2800, 2801, 2802, 2803, 2808, 2809, 2810, 2811, 2812, 2813, 2814, 2815, 2820,
            2821, 2822, 2823, 2824, 2825, 2826, 2827, 2832, 2833, 2834, 2835, 2836, 2837, 2838,
            2839, 2844, 2845, 2846, 2847, 2848, 2849, 2850, 2851, 2856, 2857, 2858, 2859, 2860,
            2861, 2862, 2863, 2868, 2869, 2870, 2871, 2872, 2873, 2874, 2875, 2880, 2881, 2882,
            2883, 2884, 2885, 2886, 2887, 2892, 2893, 2894, 2895, 2896, 2897, 2898, 2899, 2904,
            2905, 2906, 2907, 2908, 2909, 2910, 2911, 3012, 3013, 3014, 3015, 3016, 3017, 3018,
            3019, 3024, 3025, 3026, 3027, 3028, 3029, 3030, 3031, 3036, 3037, 3038, 3039, 3040,
            3041, 3042, 3043, 3048, 3049, 3050, 3051, 3052, 3053, 3054, 3055, 3060, 3061, 3062,
            3063, 3064, 3065, 3066, 3067, 3072, 3073, 3074, 3075, 3076, 3077, 3078, 3079, 3084,
            3085, 3086, 3087, 3088, 3089, 3090, 3091, 3096, 3097, 3098, 3099, 3100, 3101, 3102,
            3103, 3108, 3109, 3110, 3111, 3112, 3113, 3114, 3115, 3120, 3121, 3122, 3123, 3124,
            3125, 3126, 3127, 3132, 3133, 3134, 3135, 3136, 3137, 3138, 3139, 3144, 3145, 3146,
            3147, 3148, 3149, 3150, 3151, 3156, 3157, 3158, 3159, 3160, 3161, 3162, 3163, 3168,
            3169, 3170, 3171, 3172, 3173, 3174, 3175, 3180, 3181, 3182, 3183, 3184, 3185, 3186,
            3187, 3192, 3193, 3194, 3195, 3196, 3197, 3198, 3199, 3204, 3205, 3206, 3207, 3208,
            3209, 3210, 3211, 3312, 3313, 3314, 3315, 3316, 3317, 3318, 3319, 3324, 3325, 3326,
            3327, 3328, 3329, 3330, 3331, 3336, 3337, 3338, 3339, 3340, 3341, 3342, 3343, 3348,
            3349, 3350, 3351, 3352, 3353, 3354, 3355, 3360, 3361, 3362, 3363, 3364, 3365, 3366,
            3367, 3372, 3373, 3374, 3375, 3376, 3377, 3378, 3379, 3384, 3385, 3386, 3387, 3388,
            3389, 3390, 3391, 3396, 3397, 3398, 3399, 3400, 3401, 3402, 3403, 3408, 3409, 3410,
            3411, 3412, 3413, 3414, 3415, 3420, 3421, 3422, 3423, 3424, 3425, 3426, 3427, 3432,
            3433, 3434, 3435, 3436, 3437, 3438, 3439, 3444, 3445, 3446, 3447, 3448, 3449, 3450,
            3451, 3456, 3457, 3458, 3459, 3460, 3461, 3462, 3463, 3468, 3469, 3470, 3471, 3472,
            3473, 3474, 3475, 3480, 3481, 3482, 3483, 3484, 3485, 3486, 3487, 3492, 3493, 3494,
            3495, 3496, 3497, 3498, 3499, 3504, 3505, 3506, 3507, 3508, 3509, 3510, 3511, 3612,
            3613, 3614, 3615, 3616, 3617, 3618, 3619, 3624, 3625, 3626, 3627, 3628, 3629, 3630,
            3631, 3636, 3637, 3638, 3639, 3640, 3641, 3642, 3643, 3648, 3649, 3650, 3651, 3652,
            3653, 3654, 3655, 3660, 3661, 3662, 3663, 3664, 3665, 3666, 3667, 3672, 3673, 3674,
            3675, 3676, 3677, 3678, 3679, 3684, 3685, 3686, 3687, 3688, 3689, 3690, 3691, 3696,
            3697, 3698, 3699, 3700, 3701, 3702, 3703, 3708, 3709, 3710, 3711, 3712, 3713, 3714,
            3715, 3720, 3721, 3722, 3723, 3724, 3725, 3726, 3727, 3732, 3733, 3734, 3735, 3736,
            3737, 3738, 3739, 3744, 3745, 3746, 3747, 3748, 3749, 3750, 3751, 3756, 3757, 3758,
            3759, 3760, 3761, 3762, 3763, 3768, 3769, 3770, 3771, 3772, 3773, 3774, 3775, 3780,
            3781, 3782, 3783, 3784, 3785, 3786, 3787, 3792, 3793, 3794, 3795, 3796, 3797, 3798,
            3799, 3804, 3805, 3806, 3807, 3808, 3809, 3810, 3811, 3912, 3913, 3914, 3915, 3916,
            3917, 3918, 3919, 3924, 3925, 3926, 3927, 3928, 3929, 3930, 3931, 3936, 3937, 3938,
            3939, 3940, 3941, 3942, 3943, 3948, 3949, 3950, 3951, 3952, 3953, 3954, 3955, 3960,
            3961, 3962, 3963, 3964, 3965, 3966, 3967, 3972, 3973, 3974, 3975, 3976, 3977, 3978,
            3979, 3984, 3985, 3986, 3987, 3988, 3989, 3990, 3991, 3996, 3997, 3998, 3999, 4000,
            4001, 4002, 4003, 4008, 4009, 4010, 4011, 4012, 4013, 4014, 4015, 4020, 4021, 4022,
            4023, 4024, 4025, 4026, 4027, 4032, 4033, 4034, 4035, 4036, 4037, 4038, 4039, 4044,
            4045, 4046, 4047, 4048, 4049, 4050, 4051, 4056, 4057, 4058, 4059, 4060, 4061, 4062,
            4063, 4068, 4069, 4070, 4071, 4072, 4073, 4074, 4075, 4080, 4081, 4082, 4083, 4084,
            4085, 4086, 4087, 4092, 4093, 4094, 4095, 4096, 4097, 4098, 4099, 4104, 4105, 4106,
            4107, 4108, 4109, 4110, 4111, 4212, 4213, 4214, 4215, 4216, 4217, 4218, 4219, 4224,
            4225, 4226, 4227, 4228, 4229, 4230, 4231, 4236, 4237, 4238, 4239, 4240, 4241, 4242,
            4243, 4248, 4249, 4250, 4251, 4252, 4253, 4254, 4255, 4260, 4261, 4262, 4263, 4264,
            4265, 4266, 4267, 4272, 4273, 4274, 4275, 4276, 4277, 4278, 4279, 4284, 4285, 4286,
            4287, 4288, 4289, 4290, 4291, 4296, 4297, 4298, 4299, 4300, 4301, 4302, 4303, 4308,
            4309, 4310, 4311, 4312, 4313, 4314, 4315, 4320, 4321, 4322, 4323, 4324, 4325, 4326,
            4327, 4332, 4333, 4334, 4335, 4336, 4337, 4338, 4339, 4344, 4345, 4346, 4347, 4348,
            4349, 4350, 4351, 4356, 4357, 4358, 4359, 4360, 4361, 4362, 4363, 4368, 4369, 4370,
            4371, 4372, 4373, 4374, 4375, 4380, 4381, 4382, 4383, 4384, 4385, 4386, 4387, 4392,
            4393, 4394, 4395, 4396, 4397, 4398, 4399, 4404, 4405, 4406, 4407, 4408, 4409, 4410,
            4411, 4512, 4513, 4514, 4515, 4516, 4517, 4518, 4519, 4524, 4525, 4526, 4527, 4528,
            4529, 4530, 4531, 4536, 4537, 4538, 4539, 4540, 4541, 4542, 4543, 4548, 4549, 4550,
            4551, 4552, 4553, 4554, 4555, 4560, 4561, 4562, 4563, 4564, 4565, 4566, 4567, 4572,
            4573, 4574, 4575, 4576, 4577, 4578, 4579, 4584, 4585, 4586, 4587, 4588, 4589, 4590,
            4591, 4596, 4597, 4598, 4599, 4600, 4601, 4602, 4603, 4608, 4609, 4610, 4611, 4612,
            4613, 4614, 4615, 4620, 4621, 4622, 4623, 4624, 4625, 4626, 4627, 4632, 4633, 4634,
            4635, 4636, 4637, 4638, 4639, 4644, 4645, 4646, 4647, 4648, 4649, 4650, 4651, 4656,
            4657, 4658, 4659, 4660, 4661, 4662, 4663, 4668, 4669, 4670, 4671, 4672, 4673, 4674,
            4675, 4680, 4681, 4682, 4683, 4684, 4685, 4686, 4687, 4692, 4693, 4694, 4695, 4696,
            4697, 4698, 4699, 4704, 4705, 4706, 4707, 4708, 4709, 4710, 4711, 4812, 4813, 4814,
            4815, 4816, 4817, 4818, 4819, 4824, 4825, 4826, 4827, 4828, 4829, 4830, 4831, 4836,
            4837, 4838, 4839, 4840, 4841, 4842, 4843, 4848, 4849, 4850, 4851, 4852, 4853, 4854,
            4855, 4860, 4861, 4862, 4863, 4864, 4865, 4866, 4867, 4872, 4873, 4874, 4875, 4876,
            4877, 4878, 4879, 4884, 4885, 4886, 4887, 4888, 4889, 4890, 4891, 4896, 4897, 4898,
            4899, 4900, 4901, 4902, 4903, 4908, 4909, 4910, 4911, 4912, 4913, 4914, 4915, 4920,
            4921, 4922, 4923, 4924, 4925, 4926, 4927, 4932, 4933, 4934, 4935, 4936, 4937, 4938,
            4939, 4944, 4945, 4946, 4947, 4948, 4949, 4950, 4951, 4956, 4957, 4958, 4959, 4960,
            4961, 4962, 4963, 4968, 4969, 4970, 4971, 4972, 4973, 4974, 4975, 4980, 4981, 4982,
            4983, 4984, 4985, 4986, 4987, 4992, 4993, 4994, 4995, 4996, 4997, 4998, 4999, 5004,
            5005, 5006, 5007, 5008, 5009, 5010, 5011, 5112, 5113, 5114, 5115, 5116, 5117, 5118,
            5119, 5124, 5125, 5126, 5127, 5128, 5129, 5130, 5131, 5136, 5137, 5138, 5139, 5140,
            5141, 5142, 5143, 5148, 5149, 5150, 5151, 5152, 5153, 5154, 5155, 5160, 5161, 5162,
            5163, 5164, 5165, 5166, 5167, 5172, 5173, 5174, 5175, 5176, 5177, 5178, 5179, 5184,
            5185, 5186, 5187, 5188, 5189, 5190, 5191, 5196, 5197, 5198, 5199, 5200, 5201, 5202,
            5203, 5208, 5209, 5210, 5211, 5212, 5213, 5214, 5215, 5220, 5221, 5222, 5223, 5224,
            5225, 5226, 5227, 5232, 5233, 5234, 5235, 5236, 5237, 5238, 5239, 5244, 5245, 5246,
            5247, 5248, 5249, 5250, 5251, 5256, 5257, 5258, 5259, 5260, 5261, 5262, 5263, 5268,
            5269, 5270, 5271, 5272, 5273, 5274, 5275, 5280, 5281, 5282, 5283, 5284, 5285, 5286,
            5287, 5292, 5293, 5294, 5295, 5296, 5297, 5298, 5299, 5304, 5305, 5306, 5307, 5308,
            5309, 5310, 5311, 5412, 5413, 5414, 5415, 5416, 5417, 5418, 5419, 5424, 5425, 5426,
            5427, 5428, 5429, 5430, 5431, 5436, 5437, 5438, 5439, 5440, 5441, 5442, 5443, 5448,
            5449, 5450, 5451, 5452, 5453, 5454, 5455, 5460, 5461, 5462, 5463, 5464, 5465, 5466,
            5467, 5472, 5473, 5474, 5475, 5476, 5477, 5478, 5479, 5484, 5485, 5486, 5487, 5488,
            5489, 5490, 5491, 5496, 5497, 5498, 5499, 5500, 5501, 5502, 5503, 5508, 5509, 5510,
            5511, 5512, 5513, 5514, 5515, 5520, 5521, 5522, 5523, 5524, 5525, 5526, 5527, 5532,
            5533, 5534, 5535, 5536, 5537, 5538, 5539, 5544, 5545, 5546, 5547, 5548, 5549, 5550,
            5551, 5556, 5557, 5558, 5559, 5560, 5561, 5562, 5563, 5568, 5569, 5570, 5571, 5572,
            5573, 5574, 5575, 5580, 5581, 5582, 5583, 5584, 5585, 5586, 5587, 5592, 5593, 5594,
            5595, 5596, 5597, 5598, 5599, 5604, 5605, 5606, 5607, 5608, 5609, 5610, 5611, 5712,
            5713, 5714, 5715, 5716, 5717, 5718, 5719, 5724, 5725, 5726, 5727, 5728, 5729, 5730,
            5731, 5736, 5737, 5738, 5739, 5740, 5741, 5742, 5743, 5748, 5749, 5750, 5751, 5752,
            5753, 5754, 5755, 5760, 5761, 5762, 5763, 5764, 5765, 5766, 5767, 5772, 5773, 5774,
            5775, 5776, 5777, 5778, 5779, 5784, 5785, 5786, 5787, 5788, 5789, 5790, 5791, 5796,
            5797, 5798, 5799, 5800, 5801, 5802, 5803, 5808, 5809, 5810, 5811, 5812, 5813, 5814,
            5815, 5820, 5821, 5822, 5823, 5824, 5825, 5826, 5827, 5832, 5833, 5834, 5835, 5836,
            5837, 5838, 5839, 5844, 5845, 5846, 5847, 5848, 5849, 5850, 5851, 5856, 5857, 5858,
            5859, 5860, 5861, 5862, 5863, 5868, 5869, 5870, 5871, 5872, 5873, 5874, 5875, 5880,
            5881, 5882, 5883, 5884, 5885, 5886, 5887, 5892, 5893, 5894, 5895, 5896, 5897, 5898,
            5899, 5904, 5905, 5906, 5907, 5908, 5909, 5910, 5911, 6012, 6013, 6014, 6015, 6016,
            6017, 6018, 6019, 6024, 6025, 6026, 6027, 6028, 6029, 6030, 6031, 6036, 6037, 6038,
            6039, 6040, 6041, 6042, 6043, 6048, 6049, 6050, 6051, 6052, 6053, 6054, 6055, 6060,
            6061, 6062, 6063, 6064, 6065, 6066, 6067, 6072, 6073, 6074, 6075, 6076, 6077, 6078,
            6079, 6084, 6085, 6086, 6087, 6088, 6089, 6090, 6091, 6096, 6097, 6098, 6099, 6100,
            6101, 6102, 6103, 6108, 6109, 6110, 6111, 6112, 6113, 6114, 6115, 6120, 6121, 6122,
            6123, 6124, 6125, 6126, 6127, 6132, 6133, 6134, 6135, 6136, 6137, 6138, 6139, 6144,
            6145, 6146, 6147, 6148, 6149, 6150, 6151, 6156, 6157, 6158, 6159, 6160, 6161, 6162,
            6163, 6168, 6169, 6170, 6171, 6172, 6173, 6174, 6175, 6180, 6181, 6182, 6183, 6184,
            6185, 6186, 6187, 6192, 6193, 6194, 6195, 6196, 6197, 6198, 6199, 6204, 6205, 6206,
            6207, 6208, 6209, 6210, 6211, 6312, 6313, 6314, 6315, 6316, 6317, 6318, 6319, 6324,
            6325, 6326, 6327, 6328, 6329, 6330, 6331, 6336, 6337, 6338, 6339, 6340, 6341, 6342,
            6343, 6348, 6349, 6350, 6351, 6352, 6353, 6354, 6355, 6360, 6361, 6362, 6363, 6364,
            6365, 6366, 6367, 6372, 6373, 6374, 6375, 6376, 6377, 6378, 6379, 6384, 6385, 6386,
            6387, 6388, 6389, 6390, 6391, 6396, 6397, 6398, 6399, 6400, 6401, 6402, 6403, 6408,
            6409, 6410, 6411, 6412, 6413, 6414, 6415, 6420, 6421, 6422, 6423, 6424, 6425, 6426,
            6427, 6432, 6433, 6434, 6435, 6436, 6437, 6438, 6439, 6444, 6445, 6446, 6447, 6448,
            6449, 6450, 6451, 6456, 6457, 6458, 6459, 6460, 6461, 6462, 6463, 6468, 6469, 6470,
            6471, 6472, 6473, 6474, 6475, 6480, 6481, 6482, 6483, 6484, 6485, 6486, 6487, 6492,
            6493, 6494, 6495, 6496, 6497, 6498, 6499, 6504, 6505, 6506, 6507, 6508, 6509, 6510,
            6511, 6612, 6613, 6614, 6615, 6616, 6617, 6618, 6619, 6624, 6625, 6626, 6627, 6628,
            6629, 6630, 6631, 6636, 6637, 6638, 6639, 6640, 6641, 6642, 6643, 6648, 6649, 6650,
            6651, 6652, 6653, 6654, 6655, 6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6672,
            6673, 6674, 6675, 6676, 6677, 6678, 6679, 6684, 6685, 6686, 6687, 6688, 6689, 6690,
            6691, 6696, 6697, 6698, 6699, 6700, 6701, 6702, 6703, 6708, 6709, 6710, 6711, 6712,
            6713, 6714, 6715, 6720, 6721, 6722, 6723, 6724, 6725, 6726, 6727, 6732, 6733, 6734,
            6735, 6736, 6737, 6738, 6739, 6744, 6745, 6746, 6747, 6748, 6749, 6750, 6751, 6756,
            6757, 6758, 6759, 6760, 6761, 6762, 6763, 6768, 6769, 6770, 6771, 6772, 6773, 6774,
            6775, 6780, 6781, 6782, 6783, 6784, 6785, 6786, 6787, 6792, 6793, 6794, 6795, 6796,
            6797, 6798, 6799, 6804, 6805, 6806, 6807, 6808, 6809, 6810, 6811, 6912, 6913, 6914,
            6915, 6916, 6917, 6918, 6919, 6924, 6925, 6926, 6927, 6928, 6929, 6930, 6931, 6936,
            6937, 6938, 6939, 6940, 6941, 6942, 6943, 6948, 6949, 6950, 6951, 6952, 6953, 6954,
            6955, 6960, 6961, 6962, 6963, 6964, 6965, 6966, 6967, 6972, 6973, 6974, 6975, 6976,
            6977, 6978, 6979, 6984, 6985, 6986, 6987, 6988, 6989, 6990, 6991, 6996, 6997, 6998,
            6999, 7000, 7001, 7002, 7003, 7008, 7009, 7010, 7011, 7012, 7013, 7014, 7015, 7020,
            7021, 7022, 7023, 7024, 7025, 7026, 7027, 7032, 7033, 7034, 7035, 7036, 7037, 7038,
            7039, 7044, 7045, 7046, 7047, 7048, 7049, 7050, 7051, 7056, 7057, 7058, 7059, 7060,
            7061, 7062, 7063, 7068, 7069, 7070, 7071, 7072, 7073, 7074, 7075, 7080, 7081, 7082,
            7083, 7084, 7085, 7086, 7087, 7092, 7093, 7094, 7095, 7096, 7097, 7098, 7099, 7104,
            7105, 7106, 7107, 7108, 7109, 7110, 7111, 7212, 7213, 7214, 7215, 7216, 7217, 7218,
            7219, 7224, 7225, 7226, 7227, 7228, 7229, 7230, 7231, 7236, 7237, 7238, 7239, 7240,
            7241, 7242, 7243, 7248, 7249, 7250, 7251, 7252, 7253, 7254, 7255, 7260, 7261, 7262,
            7263, 7264, 7265, 7266, 7267, 7272, 7273, 7274, 7275, 7276, 7277, 7278, 7279, 7284,
            7285, 7286, 7287, 7288, 7289, 7290, 7291, 7296, 7297, 7298, 7299, 7300, 7301, 7302,
            7303, 7308, 7309, 7310, 7311, 7312, 7313, 7314, 7315, 7320, 7321, 7322, 7323, 7324,
            7325, 7326, 7327, 7332, 7333, 7334, 7335, 7336, 7337, 7338, 7339, 7344, 7345, 7346,
            7347, 7348, 7349, 7350, 7351, 7356, 7357, 7358, 7359, 7360, 7361, 7362, 7363, 7368,
            7369, 7370, 7371, 7372, 7373, 7374, 7375, 7380, 7381, 7382, 7383, 7384, 7385, 7386,
            7387, 7392, 7393, 7394, 7395, 7396, 7397, 7398, 7399, 7404, 7405, 7406, 7407, 7408,
            7409, 7410, 7411,
        ];
        let digest_indices = vec![
            552, 553, 554, 555, 556, 557, 558, 559, 564, 565, 566, 567, 568, 569, 570, 571, 576,
            577, 578, 579, 580, 581, 582, 583, 588, 589, 590, 591, 592, 593, 594, 595, 1152, 1153,
            1154, 1155, 1156, 1157, 1158, 1159, 1164, 1165, 1166, 1167, 1168, 1169, 1170, 1171,
            1176, 1177, 1178, 1179, 1180, 1181, 1182, 1183, 1188, 1189, 1190, 1191, 1192, 1193,
            1194, 1195, 1752, 1753, 1754, 1755, 1756, 1757, 1758, 1759, 1764, 1765, 1766, 1767,
            1768, 1769, 1770, 1771, 1776, 1777, 1778, 1779, 1780, 1781, 1782, 1783, 1788, 1789,
            1790, 1791, 1792, 1793, 1794, 1795, 2352, 2353, 2354, 2355, 2356, 2357, 2358, 2359,
            2364, 2365, 2366, 2367, 2368, 2369, 2370, 2371, 2376, 2377, 2378, 2379, 2380, 2381,
            2382, 2383, 2388, 2389, 2390, 2391, 2392, 2393, 2394, 2395, 2952, 2953, 2954, 2955,
            2956, 2957, 2958, 2959, 2964, 2965, 2966, 2967, 2968, 2969, 2970, 2971, 2976, 2977,
            2978, 2979, 2980, 2981, 2982, 2983, 2988, 2989, 2990, 2991, 2992, 2993, 2994, 2995,
            3552, 3553, 3554, 3555, 3556, 3557, 3558, 3559, 3564, 3565, 3566, 3567, 3568, 3569,
            3570, 3571, 3576, 3577, 3578, 3579, 3580, 3581, 3582, 3583, 3588, 3589, 3590, 3591,
            3592, 3593, 3594, 3595, 4152, 4153, 4154, 4155, 4156, 4157, 4158, 4159, 4164, 4165,
            4166, 4167, 4168, 4169, 4170, 4171, 4176, 4177, 4178, 4179, 4180, 4181, 4182, 4183,
            4188, 4189, 4190, 4191, 4192, 4193, 4194, 4195, 4752, 4753, 4754, 4755, 4756, 4757,
            4758, 4759, 4764, 4765, 4766, 4767, 4768, 4769, 4770, 4771, 4776, 4777, 4778, 4779,
            4780, 4781, 4782, 4783, 4788, 4789, 4790, 4791, 4792, 4793, 4794, 4795, 5352, 5353,
            5354, 5355, 5356, 5357, 5358, 5359, 5364, 5365, 5366, 5367, 5368, 5369, 5370, 5371,
            5376, 5377, 5378, 5379, 5380, 5381, 5382, 5383, 5388, 5389, 5390, 5391, 5392, 5393,
            5394, 5395, 5952, 5953, 5954, 5955, 5956, 5957, 5958, 5959, 5964, 5965, 5966, 5967,
            5968, 5969, 5970, 5971, 5976, 5977, 5978, 5979, 5980, 5981, 5982, 5983, 5988, 5989,
            5990, 5991, 5992, 5993, 5994, 5995, 6552, 6553, 6554, 6555, 6556, 6557, 6558, 6559,
            6564, 6565, 6566, 6567, 6568, 6569, 6570, 6571, 6576, 6577, 6578, 6579, 6580, 6581,
            6582, 6583, 6588, 6589, 6590, 6591, 6592, 6593, 6594, 6595, 6852, 6853, 6854, 6855,
            6856, 6857, 6858, 6859, 6864, 6865, 6866, 6867, 6868, 6869, 6870, 6871, 6876, 6877,
            6878, 6879, 6880, 6881, 6882, 6883, 6888, 6889, 6890, 6891, 6892, 6893, 6894, 6895,
            7152, 7153, 7154, 7155, 7156, 7157, 7158, 7159, 7164, 7165, 7166, 7167, 7168, 7169,
            7170, 7171, 7176, 7177, 7178, 7179, 7180, 7181, 7182, 7183, 7188, 7189, 7190, 7191,
            7192, 7193, 7194, 7195, 7452, 7453, 7454, 7455, 7456, 7457, 7458, 7459, 7464, 7465,
            7466, 7467, 7468, 7469, 7470, 7471, 7476, 7477, 7478, 7479, 7480, 7481, 7482, 7483,
            7488, 7489, 7490, 7491, 7492, 7493, 7494, 7495,
        ];
        return (preimage_indices, digest_indices);
    }

    let mut preimage_indices = vec![];
    let mut digest_indices = vec![];
    let mut round_ctr = 0;

    for preimage in preimages.iter().take(MAX_AGG_SNARKS + 1) {
        //  136 = 17 * 8 is the size in bits of each
        //  input chunk that can be processed by Keccak circuit using absorb
        //  each chunk of size 136 needs 300 Keccak circuit rows to prove
        //  which consists of 12 Keccak rows for each of 24 + 1 Keccak cicuit rounds
        //  digest only happens at the end of the last input chunk with
        //  4 Keccak circuit rounds, so 48 Keccak rows, and 300 - 48 = 256
        let num_rounds = 1 + preimage.len() / 136;
        let mut preimage_padded = preimage.clone();
        preimage_padded.resize(136 * num_rounds, 0);
        for (i, round) in preimage_padded.chunks(136).enumerate() {
            // indices for preimages
            for (j, _chunk) in round.chunks(8).into_iter().enumerate() {
                for k in 0..8 {
                    preimage_indices.push(round_ctr * 300 + j * 12 + k + 12)
                }
            }
            // indices for digests
            if i == num_rounds - 1 {
                for j in 0..4 {
                    for k in 0..8 {
                        digest_indices.push(round_ctr * 300 + j * 12 + k + 252)
                    }
                }
            }
            round_ctr += 1;
        }
    }
    // last hash is for data_hash and has various length, so we output all the possible cells
    for _i in 0..3 {
        for (j, _) in (0..136).into_iter().chunks(8).into_iter().enumerate() {
            for k in 0..8 {
                preimage_indices.push(round_ctr * 300 + j * 12 + k + 12)
            }
        }
        for j in 0..4 {
            for k in 0..8 {
                digest_indices.push(round_ctr * 300 + j * 12 + k + 252)
            }
        }
        round_ctr += 1;
    }

    debug_assert!(is_ascending(&preimage_indices));
    debug_assert!(is_ascending(&digest_indices));

    (preimage_indices, digest_indices)
}

#[inline]
// assert two cells have same value
// (NOT constraining equality in circuit)
pub(crate) fn assert_equal<F: Field>(a: &AssignedCell<F, F>, b: &AssignedCell<F, F>) {
    let mut t1 = F::default();
    let mut t2 = F::default();
    a.value().map(|f| t1 = *f);
    b.value().map(|f| t2 = *f);
    assert_eq!(t1, t2)
}

#[inline]
// if cond = 1, assert two cells have same value;
// else the first cell is 0
// (NOT constraining equality in circuit)
pub(crate) fn assert_conditional_equal<F: Field>(
    a: &AssignedCell<F, F>,
    b: &AssignedCell<F, F>,
    cond: &AssignedValue<F>,
) {
    let mut t1 = F::default();
    let mut t2 = F::default();
    let mut c = F::default();
    a.value().map(|f| t1 = *f);
    b.value().map(|f| t2 = *f);
    cond.value().map(|f| c = *f);
    if c == F::one() {
        assert_eq!(t1, t2)
    }
}

#[inline]
// assert a \in (b1, b2, b3)
pub(crate) fn assert_exist<F: Field>(
    a: &AssignedCell<F, F>,
    b1: &AssignedCell<F, F>,
    b2: &AssignedCell<F, F>,
    b3: &AssignedCell<F, F>,
) {
    let mut t1 = F::default();
    let mut t2 = F::default();
    let mut t3 = F::default();
    let mut t4 = F::default();
    a.value().map(|f| t1 = *f);
    b1.value().map(|f| t2 = *f);
    b2.value().map(|f| t3 = *f);
    b3.value().map(|f| t4 = *f);
    assert!(t1 == t2 || t1 == t3 || t1 == t4)
}

#[inline]
// assert that the slice is ascending
fn is_ascending(a: &[usize]) -> bool {
    a.windows(2).all(|w| w[0] <= w[1])
}

/// Input values a and b, return a boolean cell a < b
pub(crate) fn is_smaller_than<F: FieldExt>(
    gate_config: &FlexGateConfig<F>,
    ctx: &mut Context<F>,
    a: &AssignedValue<F>,
    b: &AssignedValue<F>,
) -> AssignedValue<F> {
    // compute bit decomposition of a - b
    // if a < b there will be a wraparound and therefore the last bit will be 1
    // else the last bit will be 0
    let c = gate_config.sub(ctx, QuantumCell::Existing(*a), QuantumCell::Existing(*b));
    let c_bits = gate_config.num_to_bits(ctx, &c, 254);

    // println!(
    //     "a {:?}, b {:?}, c_bits {:?}",
    //     a.value,
    //     b.value,
    //     c_bits.last().unwrap().value
    // );

    *c_bits.last().unwrap()
}

#[inline]
pub(crate) fn assgined_cell_to_value(
    gate: &FlexGateConfig<Fr>,
    ctx: &mut Context<Fr>,
    assigned_cell: &AssignedCell<Fr, Fr>,
) -> AssignedValue<Fr> {
    let value = assigned_cell.value().copied();
    let assigned_value = gate.load_witness(ctx, value);
    ctx.region
        .constrain_equal(assigned_cell.cell(), assigned_value.cell)
        .unwrap();
    assigned_value
}

#[inline]
pub(crate) fn parse_hash_preimage_cells<'a>(
    hash_input_cells: &'a [AssignedCell<Fr, Fr>],
) -> (
    &'a [AssignedCell<Fr, Fr>],
    Vec<&'a [AssignedCell<Fr, Fr>]>,
    &'a [AssignedCell<Fr, Fr>],
) {
    let batch_pi_hash_preimage = &hash_input_cells[0..ROUND_LEN * 2];
    let mut chunk_pi_hash_preimages = vec![];
    for i in 0..MAX_AGG_SNARKS {
        chunk_pi_hash_preimages
            .push(&hash_input_cells[ROUND_LEN * 2 * (i + 1)..ROUND_LEN * 2 * (i + 2)]);
    }
    let potential_batch_data_hash_preimage =
        &hash_input_cells[ROUND_LEN * 2 * (MAX_AGG_SNARKS + 1)..];

    (
        batch_pi_hash_preimage,
        chunk_pi_hash_preimages,
        potential_batch_data_hash_preimage,
    )
}

#[inline]
pub(crate) fn parse_hash_digest_cells<'a>(
    hash_output_cells: &'a [AssignedCell<Fr, Fr>],
) -> (
    &'a [AssignedCell<Fr, Fr>],
    Vec<&'a [AssignedCell<Fr, Fr>]>,
    &'a [AssignedCell<Fr, Fr>],
) {
    let batch_pi_hash_digest = &hash_output_cells[0..DIGEST_LEN];
    let mut chunk_pi_hash_digests = vec![];
    for i in 0..MAX_AGG_SNARKS {
        chunk_pi_hash_digests.push(&hash_output_cells[DIGEST_LEN * (i + 1)..DIGEST_LEN * (i + 2)]);
    }
    let potential_batch_data_hash_digest = &hash_output_cells[DIGEST_LEN * (MAX_AGG_SNARKS + 1)..];
    (
        batch_pi_hash_digest,
        chunk_pi_hash_digests,
        potential_batch_data_hash_digest,
    )
}
