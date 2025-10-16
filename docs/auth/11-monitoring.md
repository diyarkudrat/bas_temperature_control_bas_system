# Monitoring & Maintenance

## 📈 Monitoring & Maintenance

### Key Metrics to Watch
- **Login success rate**: Should be > 95% for legitimate users
- **Session duration**: Average should be reasonable (not too short/long)
- **Failed attempts**: Sudden spikes may indicate attack
- **Rate limit hits**: Should be rare for normal usage

### Regular Maintenance
- **Review audit logs**: Weekly security review
- **Clean expired sessions**: Automatic, but monitor cleanup frequency
- **Update passwords**: Regular rotation for admin accounts
- **Monitor performance**: Session validation should be < 5ms
