package org.koreait.member;

import lombok.Builder;
import lombok.Data;
import org.koreait.member.entities.Member;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

@Data
@Builder
public class MemberInfo implements UserDetails {

    private String email;
    private String password;
    private Collection<? extends GrantedAuthority> authorities;
    private Member member;

    @Override
    public String getUsername() {

        return member == null ? null : member.getEmail();
    }

    @Override
    public String getPassword() {

        return member == null ? null : member.getPassword();
    }

    // 회원 탈퇴 여부
    @Override
    public boolean isEnabled() {
        return member != null && member.getDeletedAt() == null;
    }

    // 비밀번호가 만료 되지 않았는지
    @Override
    public boolean isCredentialsNonExpired() {
        return member != null && member.getCredentialChangedAt().isAfter(LocalDateTime.now().minusDays(30L));
    }

    // 권한 설정 - 인가 통제
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return member == null ? null : List.of(new SimpleGrantedAuthority(member.getAuthority().name()));
    }

    // 계정이 만료 되지 않았는지
    @Override
    public boolean isAccountNonExpired() {
        return member != null && member.getExpired() == null;
    }

    // 계정이 잠겨 있지 않는지
    @Override
    public boolean isAccountNonLocked() {
        return member != null && !member.isLocked();
    }
}
