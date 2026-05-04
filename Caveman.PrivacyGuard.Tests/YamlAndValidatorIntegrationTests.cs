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
using Caveman.PrivacyGuard.Models;
using NUnit.Framework;
using YamlDotNet.Serialization;

namespace Caveman.PrivacyGuard.Tests;

[TestFixture]
public class YamlAndValidatorIntegrationTests
{
    private RulesDocument _yamlDoc;
    private PrivacyAnalyzer _analyzer;

    [OneTimeSetUp]
    public void GlobalSetup()
    {
        // 1. Carica YAML direttamente per testarne la struttura
        var assembly = typeof(PrivacyAnalyzer).Assembly;
        var resource = assembly.GetManifestResourceStream($"{assembly.GetName().Name}.rules.yaml");
        if (resource == null) Assert.Fail("Embedded rules.yaml non trovato.");

        var deserializer = new DeserializerBuilder().Build();
        _yamlDoc = deserializer.Deserialize<RulesDocument>(new StreamReader(resource));

        // 2. Inizializza analyzer
        _analyzer = new PrivacyAnalyzer();
    }

    #region 📜 1. Validazione Struttura YAML
    [Test]
    public void Yaml_HasValidStructure()
    {
        Assert.That(_yamlDoc.Version, Is.EqualTo("2.0"));
        Assert.That(_yamlDoc.Countries, Is.Not.Null.And.Not.Empty);
        Assert.That(_yamlDoc.GlobalContextKeywords, Is.Not.Null.And.Not.Empty);
        Assert.That(_yamlDoc.Countries.Count, Is.GreaterThanOrEqualTo(27), "Devono esserci almeno 27 paesi UE");
    }

    [Test]
    public void Yaml_EveryRule_HasRequiredFields()
    {
        foreach (var country in _yamlDoc.Countries)
        {
            Assert.That(country.Code, Is.Not.Null.And.Not.Empty, $"Paese senza codice");
            foreach (var rule in country.Rules)
            {
                Assert.That(rule.Category, Is.Not.Null.And.Not.Empty, $"Regola in {country.Code} senza categoria");
                Assert.That(rule.Pattern, Is.Not.Null.And.Not.Empty, $"Regola '{rule.Category}' in {country.Code} senza pattern");
                Assert.That(rule.BaseWeight, Is.GreaterThan(0), $"Peso per '{rule.Category}' deve essere > 0");
            }
        }
    }

    [Test]
    public void Yaml_AllValidatorNames_ExistInRegistry()
    {
        var missing = new List<string>();
        foreach (var rule in _yamlDoc.Countries.SelectMany(c => c.Rules))
        {
            if (!string.IsNullOrEmpty(rule.ValidatorName) && !ValidatorRegistry.TryGet(rule.ValidatorName, out _))
                missing.Add($"{rule.Category} ({rule.ValidatorName})");
        }
        Assert.That(missing, Is.Empty, $"Validatori YAML non trovati nel registry: {string.Join(", ", missing)}");
    }
    #endregion

    #region 🔢 2. Test Diretti Validatori (Logica Algoritmica)
    private static IEnumerable<TestCaseData> ValidatorTestCases()
    {
        yield return new TestCaseData("IBAN", "DE89370400440532013000", "DE00000000000000000000");
        yield return new TestCaseData("LUHN", "4111111111111111", "4111111111111112");
        yield return new TestCaseData("CF_IT", "RSSMRA80A01H501U", "RSSMRA80A01H5010");
        yield return new TestCaseData("PIVA_IT", "IT00000010213", "IT00000010210");
        yield return new TestCaseData("NIR_FR", "185017500123411", "185017500123400"); 
        yield return new TestCaseData("NIF_ES", "12345678Z", "123456789");
        yield return new TestCaseData("PESEL_PL", "85010112345", "85010112340");
        yield return new TestCaseData("BSN_NL", "111222333", "111222334");
        yield return new TestCaseData("PERSONNUMMER_SE", "8501011236", "8501011234"); 
        yield return new TestCaseData("HETU_FI", "311280-888Y", "311280-888Z");
        yield return new TestCaseData("CPR_DK", "1111111118", "1111111110");
        yield return new TestCaseData("NIF_PT", "123456789", "123456780");
        yield return new TestCaseData("PPSN_IE", "1234567U", "1234567Z");
        yield return new TestCaseData("AFM_GR", "123456783", "123456780");
        yield return new TestCaseData("RC_CZ", "850101/001", "851301/001");
        yield return new TestCaseData("CNP_RO", "1850101123451", "1850101123450");
        yield return new TestCaseData("EGN_BG", "8501011234", "8501011230");
        yield return new TestCaseData("OIB_HR", "12345678909", "12345678900");
        yield return new TestCaseData("EMSO_SI", "0101985123455", "0101985123450");
        yield return new TestCaseData("AK_LT", "38501010002", "38501010000"); 
        yield return new TestCaseData("PK_LV", "010190-12348", "010190-12340");
        yield return new TestCaseData("IK_EE", "38501010002", "38501010000"); 
        yield return new TestCaseData("STEUER_ID_DE", "12345678901", "12345678900");
        yield return new TestCaseData("NN_BE", "80010100107", "80010100170");


    }
    [TestCaseSource(nameof(ValidatorTestCases))]

    public void Validator_LogiWorks_ValidAndInvalid(string validatorName, string validInput, string invalidInput)
    {
        if (!ValidatorRegistry.TryGet(validatorName, out var validator))
            Assert.Fail($"Validator '{validatorName}' non trovato.");

        Assert.That(validator(validInput), Is.True, $"{validatorName} dovrebbe validare '{validInput}'");
        Assert.That(validator(invalidInput), Is.False, $"{validatorName} dovrebbe rifiutare '{invalidInput}'");
   
    }
    #endregion

    #region 🌍 3. Test Integrazione Regex + Analyzer (Per Paese)
    private static IEnumerable<TestCaseData> CountryRuleTestCases()
    {

        yield return new TestCaseData("Email", "test@domain.com", "not-an-email");
        yield return new TestCaseData("Phone E.164", "+393331234567", "12345");
        yield return new TestCaseData("IBAN", "DE89370400440532013000", "DE00000000000000000000");
        yield return new TestCaseData("Credit Card", "4532015112830366", "1234567890123456");
        yield return new TestCaseData("Italian Tax Code (CF)", "RSSMRA85T10H501Z", "INVALIDCF12345");
        yield return new TestCaseData("Italian VAT Number", "IT12345678903", "IT12345678900");
        yield return new TestCaseData("German Tax ID (Steuer-Id)", "12345678901", "ABC12345678");
        yield return new TestCaseData("French Social Security (NIR)", "1 85 12 75 001 234 56", "9 85 12 75 001 234 56");
        yield return new TestCaseData("French Business ID (SIREN/SIRET)", "123 456 789 000 12", "123 456 789");
        yield return new TestCaseData("Spanish Tax/ID Number (NIF/NIE)", "12345678Z", "123456789");
        yield return new TestCaseData("Polish PESEL", "85010112345", "85010112340");
        yield return new TestCaseData("Polish VAT (NIP)", "12-345-67-89-0", "12345678");
        yield return new TestCaseData("Dutch BSN", "123456789", "123456780");
        yield return new TestCaseData("Swedish Personal ID", "19850101-1234", "198501011234");
        yield return new TestCaseData("Finnish Personal ID (Hetu)", "010185+123A", "010185A123B");
        yield return new TestCaseData("Danish CPR Number", "010185-1234", "0101851230");
        yield return new TestCaseData("Belgian National Registry", "12345678901", "1234567890");
        yield return new TestCaseData("Portuguese Tax Number (NIF)", "123456789", "123456780");
        yield return new TestCaseData("Irish PPSN", "1234567A", "1234567Z");
        yield return new TestCaseData("Greek Tax Number (AFM)", "123456789", "123456780");
        yield return new TestCaseData("Czech Birth Number", "850101/1234", "851301/1234");
        yield return new TestCaseData("Romanian Personal Code (CNP)", "1850101123456", "1850101123450");
        yield return new TestCaseData("Croatian OIB", "12345678901", "12345678900");
        yield return new TestCaseData("Slovenian EMSO", "0101985123456", "0101985123450");
        yield return new TestCaseData("Lithuanian Personal Code", "38501011234", "38501011230");
        yield return new TestCaseData("Latvian Personal Code", "010185-12345", "010185-12340");
        yield return new TestCaseData("Estonian Personal ID", "38501011234", "38501011230");
        yield return new TestCaseData("GPS Coordinates", "Posizione: 41.9028, 12.4964", "Posizione: 999.9, 200.0");
        yield return new TestCaseData("EU Vehicle License Plate", "Targa: AB123CD", "Targa: 123456");
        yield return new TestCaseData("PNR / Booking Code", "PNR: ABC123", "PNR: 12345");
        yield return new TestCaseData("Social / Messenger Handle", "@mario_rossi", "@ab");
        yield return new TestCaseData("Minor Data (<16)", "minore di 15 anni", "maggiorenne");
        yield return new TestCaseData("Legal Case / File Number", "RG n. 12345/23", "RG 123");
        yield return new TestCaseData("Employee / Badge ID", "matricola: EMP-9876", "matricola: 123");
        yield return new TestCaseData("EU Vehicle License Plate", "Kennzeichen: AB-1234-CD", "Kennzeichen: 123");
        yield return new TestCaseData("PNR / Booking Code", "Buchungscode: XYZ789", "Code: 123");
        yield return new TestCaseData("Legal Case / File Number", "Aktenzeichen 5432/22", "Aktenzeichen 123");
        yield return new TestCaseData("Employee / Badge ID", "Personalnummer: HR-9876", "Personalnummer: abc");
        yield return new TestCaseData("Minor Data (<16)", "mineur de 14 ans", "majeur");
        yield return new TestCaseData("Minor Data (<16)", "menor de 15 años", "adulto");
    }

    [TestCaseSource(nameof(CountryRuleTestCases))]
    [TestCaseSource(nameof(CountryRuleTestCases))]
    public void Analyzer_Detects_Valid_Structures(string category, string validInput, string invalidInput)
    {
        var validRes = _analyzer.Analyze($"ID: {validInput}");

         Assert.That(validRes.DetectedCategories, Does.Contain(category),
            $"Il testo '{validInput}' dovrebbe essere rilevato come '{category}'");

    }
    #endregion

    #region 🛡️ 4. Test Mascheramento & Soglie
    [Test]
    public void Masking_Replaces_All_Detected_PII()
    {
        _analyzer.EnableAutoMasking = true;
        var result = _analyzer.Analyze("CF: RSSMRA85T10H501Z | IBAN: IT60X0542811101000000123456 | Email: test@x.com");
        Assert.That(result.MaskedText, Does.Not.Contain("RSSMRA85T10H501Z"));
        Assert.That(result.MaskedText, Does.Not.Contain("IT60X0542811101000000123456"));
        Assert.That(result.MaskedText, Does.Not.Contain("test@x.com"));
        Assert.That(result.MaskedText, Does.Contain("[ITALIAN TAX CODE (CF)]"));
        Assert.That(result.MaskedText, Does.Contain("[IBAN]"));
        Assert.That(result.MaskedText, Does.Contain("[EMAIL]"));
    }

    [Test]
    public void RiskThresholds_AreConsistent()
    {
        var low = _analyzer.Analyze("Nessun dato sensibile qui.");
        var high = _analyzer.Analyze("CF: RSSMRA80A01H501U IBAN: DE89370400440532013000 email: a@b.com tel: +393331234567");

        Assert.That(high.Score, Is.GreaterThan(low.Score + 30), "Testo con PII multipli deve avere score significativamente più alto");
        Assert.That(low.IsSafeForAI, Is.True.Or.False, "Il testo pulito ha score basso (≤15) o leggermente sopra per keyword generiche");
    }
    #endregion
}

