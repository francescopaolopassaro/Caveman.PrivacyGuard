// ------------------------------------------------------------------------------
// Caveman.PrivacyGuard
// Copyright (c) 2026 Passaro Francesco Paolo
// Licensed under the MIT License. See LICENSE file in the project root.
// https://github.com/francescopaolopassaro/Caveman.PrivacyGuard
//
// Enterprise-grade PII & Privacy Analyzer for AI/LLM workflows.
// Detects, scores, and auto-masks sensitive data across 27 EU countries with 
// GDPR/PCI-DSS/NIST compliance flags, multi-language support, and YAML-driven 
// extensible rules. Thread-safe, embedded resources, zero external dependencies.
// ------------------------------------------------------------------------------
using System.Text.RegularExpressions;

namespace Caveman.PrivacyGuard;

public static class ValidatorRegistry
{
    private static readonly Dictionary<string, Func<string, bool>> _validators = new(StringComparer.OrdinalIgnoreCase)
    {
        { "IBAN", V.ValidateIBAN }, { "LUHN", V.ValidateLuhn },
        { "CF_IT", V.ValidateCF_IT }, { "PIVA_IT", V.ValidatePIVA_IT },
        { "NIR_FR", V.ValidateNIR_FR }, { "NIF_ES", V.ValidateNIF_ES },
        { "PESEL_PL", V.ValidatePESEL_PL }, { "BSN_NL", V.ValidateBSN_NL },
        { "PERSONNUMMER_SE", V.ValidatePersonnummer_SE }, { "HETU_FI", V.ValidateHetu_FI },
        { "CPR_DK", V.ValidateCPR_DK }, { "NIF_PT", V.ValidateNIF_PT },
        { "PPSN_IE", V.ValidatePPSN_IE }, { "AFM_GR", V.ValidateAFM_GR },
        { "RC_CZ", V.ValidateRC_CZ }, { "CNP_RO", V.ValidateCNP_RO },
        { "EGN_BG", V.ValidateEGN_BG }, { "OIB_HR", V.ValidateOIB_HR },
        { "EMSO_SI", V.ValidateEMSO_SI }, { "AK_LT", V.ValidateAK_LT },
        { "PK_LV", V.ValidatePK_LV }, { "IK_EE", V.ValidateIK_EE },
        { "STEUER_ID_DE", V.ValidateSteuerId_DE }, { "NN_BE", V.ValidateNN_BE }
    };

    public static void Register(string name, Func<string, bool> v) => _validators[name] = v;
    public static bool TryGet(string name, out Func<string, bool> v) => _validators.TryGetValue(name, out v);

    private static class V
    {
        internal static bool ValidateIBAN(string iban)
        {
            var c = iban.Replace(" ", "").ToUpperInvariant();
            if (!Regex.IsMatch(c, @"^[A-Z]{2}\d{2}[A-Z0-9]{4,30}$")) return false;
            string num = "";
            foreach (var ch in c.Substring(4) + c.Substring(0, 4))
                num += char.IsLetter(ch) ? (ch - 'A' + 10).ToString("D2") : ch.ToString();
            int rem = 0;
            foreach (var ch in num) rem = (rem * 10 + (ch - '0')) % 97;
            return rem == 1;
        }

        internal static bool ValidateLuhn(string num)
        {
            var d = num.Where(char.IsDigit).ToArray();
            if (d.Length < 13 || d.Length > 19) return false;
            int sum = 0, alt = 0;
            for (int i = d.Length - 1; i >= 0; i--)
            {
                int n = d[i] - '0';
                if ((alt++ & 1) == 1) { n *= 2; if (n > 9) n -= 9; }
                sum += n;
            }
            return sum % 10 == 0;
        }

        internal static bool ValidateCF_IT(string cf)
        {
            if (cf.Length != 16) return false;
            cf = cf.ToUpperInvariant();
            if (!Regex.IsMatch(cf, @"^[A-Z]{6}[0-9LMNPQRSTUV]{2}[ABCDEHLMPRST][0-9LMNPQRSTUV]{2}[A-Z][0-9LMNPQRSTUV]{3}[A-Z]$")) return false;
            int[] oddD = { 1, 0, 5, 7, 9, 13, 15, 17, 19, 21 };
            int[] oddL = { 1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23 };
            int sum = 0;
            for (int i = 0; i < 15; i++)
            {
                char c = cf[i]; bool odd = i % 2 == 0;
                if (char.IsDigit(c)) sum += odd ? oddD[c - '0'] : c - '0';
                else sum += odd ? oddL[c - 'A'] : c - 'A';
            }
            return (char)('A' + sum % 26) == cf[15];
        }

        internal static bool ValidatePIVA_IT(string piva)
        {
            var c = piva.Replace("IT", "");
            if (c.Length != 11 || !c.All(char.IsDigit)) return false;
            int[] w = { 2, 1, 2, 1, 2, 1, 2, 1, 2, 1 };
            int sum = 0;
            for (int i = 0; i < 10; i++) { int v = (c[i] - '0') * w[i]; sum += v > 9 ? v - 9 : v; }
            return (10 - sum % 10) % 10 == c[10] - '0';
        }

        internal static bool ValidateNIR_FR(string nir)
        {
            var clean = nir.Replace(" ", "");
            if (clean.Length != 15 || !clean.All(char.IsDigit)) return false;
            long first13 = long.Parse(clean.Substring(0, 13));
            int check = int.Parse(clean.Substring(13, 2));
            return (97 - (first13 % 97)) == check;
        }

        internal static bool ValidateNIF_ES(string nif)
        {
            var clean = nif.ToUpperInvariant().Replace(" ", "");
            if (clean.Length != 9 || !int.TryParse(clean.Substring(0, 8), out var n)) return false;
            return "TRWAGMYFPDXBNJZSQVHLCKE"[n % 23] == clean[8];
        }

        internal static bool ValidatePESEL_PL(string pesel)
        {
            if (pesel.Length != 11 || !pesel.All(char.IsDigit)) return false;
            int[] w = { 1, 3, 7, 9, 1, 3, 7, 9, 1, 3, 1 };
            int sum = 0;
            for (int i = 0; i < 11; i++) sum += (pesel[i] - '0') * w[i];
            return sum % 10 == 0;
        }

        internal static bool ValidateBSN_NL(string bsn)
        {
            if (bsn.Length != 9 || !bsn.All(char.IsDigit)) return false;
            int[] w = { 9, 8, 7, 6, 5, 4, 3, 2, -1 };
            int sum = 0;
            for (int i = 0; i < 9; i++) sum += (bsn[i] - '0') * w[i];
            return sum % 11 == 0;
        }

        internal static bool ValidatePersonnummer_SE(string s)
        {
            var clean = s.Replace("-", "");
            if (clean.Length != 10 || !clean.All(char.IsDigit)) return false;
            int sum = 0, alt = 0;
            for (int i = 0; i < 9; i++)
            {
                int n = (clean[i] - '0') * ((alt++ % 2 == 0) ? 2 : 1);
                sum += n > 9 ? n - 9 : n;
            }
            return (10 - sum % 10) % 10 == clean[9] - '0';
        }

        internal static bool ValidateHetu_FI(string s)
        {
            if (s.Length != 11 || "+-ABCDEF".IndexOf(s[6]) < 0) return false;
            string num = s.Substring(0, 6) + s.Substring(7, 3);
            if (!int.TryParse(num, out var n)) return false;
            return "0123456789ABCDEFHJKLMNPRSTUVWXY"[n % 31] == s[10];
        }

        internal static bool ValidateCPR_DK(string s)
        {
            var clean = s.Replace("-", "");
            if (clean.Length != 10 || !clean.All(char.IsDigit)) return false;
            int[] w = { 4, 3, 2, 7, 6, 5, 4, 3, 2, 1 };
            int sum = 0;
            for (int i = 0; i < 10; i++) sum += (clean[i] - '0') * w[i];
            return sum % 11 == 0;
        }

        internal static bool ValidateNIF_PT(string s)
        {
            if (s.Length != 9 || !s.All(char.IsDigit)) return false;
            int[] w = { 9, 8, 7, 6, 5, 4, 3, 2 };
            int sum = 0;
            for (int i = 0; i < 8; i++) sum += (s[i] - '0') * w[i];
            int ctrl = 11 - (sum % 11);
            if (ctrl >= 10) ctrl = 0;
            return ctrl == s[8] - '0';
        }

        internal static bool ValidatePPSN_IE(string s)
        {
            var clean = s.ToUpperInvariant().Replace(" ", "");
            if (clean.Length is not 8 and not 9) return false;
            if (!clean.Substring(0, 7).All(char.IsDigit)) return false;
            int[] w = { 8, 7, 6, 5, 4, 3, 2 };
            int sum = 0;
            for (int i = 0; i < 7; i++) sum += (clean[i] - '0') * w[i];
            char expected = "ABCDEFGHIJKLMNOPQRSTUVW"[sum % 23];
            if (clean[7] != expected) return false;
            return clean.Length != 9 || clean[8] == 'W';
        }

        internal static bool ValidateAFM_GR(string s)
        {
            if (s.Length != 9 || !s.All(char.IsDigit)) return false;
            int[] w = { 256, 128, 64, 32, 16, 8, 4, 2 };
            int sum = 0;
            for (int i = 0; i < 8; i++) sum += (s[i] - '0') * w[i];
            return (sum % 11) % 10 == s[8] - '0';
        }

        internal static bool ValidateRC_CZ(string s)
        {
            var clean = s.Replace("/", "");
     
            if (clean.Length is not 9 and not 10 || !clean.All(char.IsDigit)) return false;

            int y = int.Parse(clean.Substring(0, 2));
            int m = int.Parse(clean.Substring(2, 2));
            if (m > 50) m -= 50; 


            if (!DateTime.TryParseExact($"{y:D2}-{m:D2}-{clean.Substring(4, 2):D2}", "yy-MM-dd", null, System.Globalization.DateTimeStyles.None, out _))
                return false;

    
            if (clean.Length == 10)
            {
                long first9 = long.Parse(clean.Substring(0, 9));
                int check = (int)(first9 % 11);
                if (check == 10) return false; 
                return check == clean[9] - '0';
            }
            return true; 
        }

        internal static bool ValidateCNP_RO(string s)
        {
            if (s.Length != 13 || !s.All(char.IsDigit)) return false;
            int[] w = { 2, 7, 9, 1, 4, 6, 3, 5, 8, 2, 7, 9 };
            int sum = 0;
            for (int i = 0; i < 12; i++) sum += (s[i] - '0') * w[i];
            int ctrl = sum % 11;
            if (ctrl == 10) ctrl = 1;
            return ctrl == s[12] - '0';
        }

        internal static bool ValidateEGN_BG(string s)
        {
            if (s.Length != 10 || !s.All(char.IsDigit)) return false;
            int[] w = { 2, 4, 8, 5, 10, 9, 7, 3, 6 };
            int sum = 0;
            for (int i = 0; i < 9; i++) sum += (s[i] - '0') * w[i];
            return sum % 11 % 10 == s[9] - '0';
        }

        internal static bool ValidateOIB_HR(string s)
        {
            if (s.Length != 11 || !s.All(char.IsDigit)) return false;
            int sum = 0;
            for (int i = 0; i < 10; i++) sum += (s[i] - '0') * (11 - i);
            int ctrl = 11 - (sum % 11);
            if (ctrl == 10) ctrl = 0;
            return ctrl == s[10] - '0';
        }

        internal static bool ValidateEMSO_SI(string s)
        {
            if (s.Length != 13 || !s.All(char.IsDigit)) return false;
            int[] w = { 7, 6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2 };
            int sum = 0;
            for (int i = 0; i < 12; i++) sum += (s[i] - '0') * w[i];
            int ctrl = 11 - (sum % 11);
            if (ctrl >= 10) ctrl = 0;
            return ctrl == s[12] - '0';
        }

        internal static bool ValidateAK_LT(string s)
        {
            if (s.Length != 11 || !s.All(char.IsDigit)) return false;
            int[] w1 = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 1 };
            int[] w2 = { 3, 4, 5, 6, 7, 8, 9, 1, 2, 3 };
            int sum = 0;
            for (int i = 0; i < 10; i++) sum += (s[i] - '0') * w1[i];
            int ctrl = sum % 11;
            if (ctrl == 10)
            {
                sum = 0;
                for (int i = 0; i < 10; i++) sum += (s[i] - '0') * w2[i];
                ctrl = sum % 11;
                if (ctrl == 10) ctrl = 0;
            }
            return ctrl == s[10] - '0';
        }

        internal static bool ValidatePK_LV(string s)
        {
            var clean = s.Replace("-", "");
            if (clean.Length != 11 || !clean.All(char.IsDigit)) return false;
            int[] w = { 1, 6, 3, 7, 9, 10, 5, 8, 4, 2 };
            int sum = 0;
            for (int i = 0; i < 10; i++) sum += (clean[i] - '0') * w[i];
            int ctrl = 11 - (sum % 11);
            if (ctrl == 10) ctrl = 0;
            return ctrl == clean[10] - '0';
        }

        internal static bool ValidateIK_EE(string s)
        {
            if (s.Length != 11 || !s.All(char.IsDigit)) return false;
            int[] w1 = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 1 };
            int[] w2 = { 3, 4, 5, 6, 7, 8, 9, 1, 2, 3 };
            int sum = 0;
            for (int i = 0; i < 10; i++) sum += (s[i] - '0') * w1[i];
            int ctrl = sum % 11;
            if (ctrl == 10)
            {
                sum = 0;
                for (int i = 0; i < 10; i++) sum += (s[i] - '0') * w2[i];
                ctrl = sum % 11;
                if (ctrl == 10) ctrl = 0;
            }
            return ctrl == s[10] - '0';
        }

        internal static bool ValidateSteuerId_DE(string s)
        {
            if (s.Length != 11 || !s.All(char.IsDigit)) return false;
            int[] w = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
            int sum = 0;
            for (int i = 0; i < 10; i++) sum += (s[i] - '0') * w[i];
            int rem = sum % 11;
            int expected = rem == 0 ? 0 : 11 - rem;
            return expected != 10 && expected == s[10] - '0';
        }

        internal static bool ValidateNN_BE(string s)
        {
            if (s.Length != 11 || !s.All(char.IsDigit)) return false;
            long first9 = long.Parse(s.Substring(0, 9));
            int check = int.Parse(s.Substring(9, 2));
            return (97 - (first9 % 97)) % 100 == check;
        }
    }
}